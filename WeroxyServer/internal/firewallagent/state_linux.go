//go:build linux

package firewallagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stateDirectory = "/var/lib/weroxy-firewall"
const statePath = stateDirectory + "/state.json"

type savedState struct {
	ConfigDigest string `json:"config_digest"`
	Generation   uint64 `json:"generation"`
	Digest       string `json:"digest"`
	Rules        []Rule `json:"rules"`
}

func configDigest(cfg Config) string {
	body, _ := json.Marshal(cfg)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func prepareStateDirectory() error {
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return err
	}
	for path := stateDirectory; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !ok || owner.Uid != 0 {
			return errors.New("protected root-owned agent state directory required")
		}
		if path == "/" {
			break
		}
	}
	return nil
}

// Persist intent before kernel mutation. A crash retries the complete approved
// batch, rather than losing generation or extending the original expiration.
func (a *agent) saveIntent(generation uint64, rules []Rule) error {
	if err := prepareStateDirectory(); err != nil {
		return err
	}
	body, err := json.Marshal(savedState{configDigest(a.cfg), generation, DigestRules(rules), rules})
	if err != nil || len(body) > maxRequest {
		return errors.New("agent state exceeds budget")
	}
	file, err := os.CreateTemp(stateDirectory, ".state-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, statePath); err != nil {
		return err
	}
	a.intentGeneration = generation
	a.intentDigest = digestRules(rules)
	dir, err := os.Open(stateDirectory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (a *agent) recoverState(ctx context.Context) error {
	if err := prepareStateDirectory(); err != nil {
		return err
	}
	fd, err := unix.Open(statePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), statePath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Size() > maxRequest || info.Mode().Perm()&0o077 != 0 || !ok || owner.Uid != 0 {
		return errors.New("unsafe agent state file")
	}
	var saved savedState
	dec := json.NewDecoder(io.LimitReader(file, maxRequest+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&saved); err != nil {
		return errors.New("invalid agent state")
	}
	var extra any
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return errors.New("trailing agent state data")
	}
	if saved.Generation == 0 || saved.ConfigDigest != configDigest(a.cfg) || saved.Digest != DigestRules(saved.Rules) {
		return errors.New("agent state scope or digest mismatch")
	}
	validation := append([]Rule(nil), saved.Rules...)
	now := time.Now().UTC()
	for i := range validation {
		validation[i].ExpiresAt = now.Add(time.Hour)
	}
	if err := ValidateRules(a.cfg, validation, now); err != nil {
		return err
	}
	if !a.cfg.AllowApply {
		return errors.New("stored kernel rules require explicit recovery with allow_apply")
	}
	a.intentGeneration = saved.Generation
	a.intentDigest = digestRules(saved.Rules)
	active := liveRules(saved.Rules, now)
	if err := a.apply(ctx, active); err != nil {
		return err
	}
	a.generation = saved.Generation
	a.rules = append([]Rule(nil), saved.Rules...)
	a.digest = digestRules(saved.Rules)
	a.applied = true
	a.appliedActive = len(active)
	return nil
}

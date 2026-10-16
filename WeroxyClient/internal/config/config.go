// Package config reads the WeroxyClient file. It does not accept a key on the command line.
package config

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ControlPort is the Weroxy control listener. Legacy clients stay on 4900.
const ControlPort = "29999"

// Config is the client profile: server host, client key, and the control port.
type Config struct {
	Server   string
	DeviceID string
	Key      string
	KeyPath  string
}

// Load reads host, key, and port. The file must be mode 0600 because it holds the key.
func Load(path string) (Config, error) {
	body, err := readSecureFile(path, 1<<20)
	if err != nil {
		return Config{}, err
	}
	defer clear(body)
	if bytes.Equal(body, []byte(InitialProfile)) {
		return Config{}, ErrUnconfigured
	}
	var cfg Config
	var host, port string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("Configuration line is missing an equals sign")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "server.host", "host":
			host = value
		case "server.port", "port":
			port = value
		case "client.key", "key":
			cfg.Key = value
		case "client.key_file":
			cfg.KeyPath = value
		case "tls_cert", "target.allow", "target.deny_cidr", "target.deny_port":
			// Accepted only to read 0.2.0 profiles; these policies are no longer active.
		default:
			return Config{}, fmt.Errorf("Unknown configuration key")
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	if cfg.KeyPath != "" {
		if cfg.Key != "" {
			return Config{}, errors.New("Do not set both client.key and client.key_file")
		}
		if !filepath.IsAbs(cfg.KeyPath) {
			cfg.KeyPath = filepath.Join(filepath.Dir(path), cfg.KeyPath)
		}
		token, err := ReadTokenFile(cfg.KeyPath)
		if err != nil {
			return Config{}, fmt.Errorf("Unable to read the separate key file: %w", err)
		}
		cfg.Key = hex.EncodeToString(token)
		clear(token)
	}
	if host == "" || cfg.Key == "" {
		return Config{}, errors.New("Configuration requires server.host, client.key and server.port")
	}
	if port == "" {
		port = ControlPort
	}
	cfg.Server = net.JoinHostPort(host, port)
	if _, err := canonical(cfg.Server); err != nil {
		return Config{}, fmt.Errorf("Invalid Server address")
	}
	if _, err := decodeToken([]byte(cfg.Key)); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ReadTokenFile reads a 32-byte token encoded as hex. The file mode must be 0600.
func ReadTokenFile(path string) ([]byte, error) {
	body, err := readSecureFile(path, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	return decodeToken(body)
}

// ReadToken reads a hex token from a reader, usually standard input.
func ReadToken(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, 256))
	if err != nil {
		return nil, err
	}
	return decodeToken(body)
}

func decodeToken(body []byte) ([]byte, error) {
	text := strings.TrimSpace(string(body))
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("Token must contain 64 hexadecimal characters")
	}
	return raw, nil
}

// Save atomically replaces the Host, Port and Key profile.
func Save(path, host, key, port string) error {
	if port == "" {
		port = ControlPort
	}
	if _, err := decodeToken([]byte(key)); err != nil {
		return err
	}
	if strings.ContainsAny(host, "\r\n\t =") {
		return errors.New("Invalid Server address")
	}
	server := net.JoinHostPort(host, port)
	if _, err := canonical(server); err != nil {
		return fmt.Errorf("Invalid Server address")
	}
	var body strings.Builder
	body.WriteString("server.host=" + host + "\nserver.port=" + port + "\n")
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var oldKeyPath string
	if current, err := Load(path); err == nil {
		oldKeyPath = current.KeyPath
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrUnconfigured) {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("Legacy configuration must be a size-bounded regular file")
		}
		body, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		backup, e := os.OpenFile(path+".repair-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".bak", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = backup.Write(body)
		backup.Close()
		if e != nil {
			return e
		}
	}
	secret, err := os.CreateTemp(dir, ".weroxy-key-*")
	if err != nil {
		return err
	}
	secretPath := secret.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(secretPath)
		}
	}()
	if err := secret.Chmod(0o600); err != nil {
		secret.Close()
		return err
	}
	if err := restrictReplacement(secretPath, path); err != nil {
		secret.Close()
		return err
	}
	if _, err := io.WriteString(secret, strings.TrimSpace(key)+"\n"); err != nil {
		secret.Close()
		return err
	}
	if err := secret.Sync(); err != nil {
		secret.Close()
		return err
	}
	if err := secret.Close(); err != nil {
		return err
	}
	body.WriteString("client.key_file=" + filepath.Base(secretPath) + "\n")
	file, err := os.CreateTemp(dir, ".weroxy-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := restrictReplacement(file.Name(), path); err != nil {
		file.Close()
		return err
	}
	if _, err := io.WriteString(file, body.String()); err != nil {
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
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	committed = true
	// Only remove generated files owned by this profile directory.
	if oldKeyPath != "" && filepath.Clean(filepath.Dir(oldKeyPath)) == filepath.Clean(dir) && strings.HasPrefix(filepath.Base(oldKeyPath), ".weroxy-key-") {
		_ = os.Remove(oldKeyPath)
	}
	return nil
}

func NormalizeTarget(value string) (string, error) { return canonical(value) }

func canonical(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\t =") {
		return "", errors.New("invalid address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

// Enforce the budget while reading, not only against an earlier stat result.
func readSecureFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || secureProfile(path, info) != nil {
		return nil, errors.New("Invalid profile/key file permissions, type or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || secureProfile(path, opened) != nil {
		return nil, errors.New("Profile or key file changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		clear(body)
		return nil, errors.New("Unable to read profile/key file or size budget exceeded")
	}
	return body, nil
}

// SaveTrust atomically stores a validated trust anchor with restricted permissions.

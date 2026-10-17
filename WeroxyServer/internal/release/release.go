// Package release reads public Weroxy releases without user credentials.
package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const API = "https://api.github.com/repos/XLYing23333/Weroxy/releases/"
const DownloadPrefix = "https://github.com/XLYing23333/Weroxy/releases/download/"

var versionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}
type Release struct {
	Tag        string  `json:"tag_name"`
	URL        string  `json:"html_url"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

func Version(s string) ([3]uint64, error) {
	var v [3]uint64
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return v, errors.New("Invalid stable release version")
	}
	for i := range v {
		n, e := strconv.ParseUint(m[i+1], 10, 64)
		if e != nil {
			return v, e
		}
		v[i] = n
	}
	return v, nil
}
func Newer(candidate, current string) bool {
	a, e := Version(candidate)
	if e != nil {
		return false
	}
	b, e := Version(current)
	if e != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.Scheme != "https" || r.URL.User != nil {
			return errors.New("Unsafe download redirect")
		}
		h := r.URL.Hostname()
		if h != "github.com" && h != "api.github.com" && h != "release-assets.githubusercontent.com" && h != "objects.githubusercontent.com" {
			return errors.New("Unexpected download host")
		}
		return nil
	}}
}
func request(ctx context.Context, c *http.Client, address string) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "Weroxy-update")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, e := c.Do(req)
	if e != nil {
		return nil, errors.New("GitHub request failed")
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("GitHub returned HTTP %d", res.StatusCode)
	}
	return res, nil
}
func read(ctx context.Context, address string, limit int64) ([]byte, error) {
	res, e := request(ctx, client(10*time.Second), address)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("Release metadata exceeds size limit")
	}
	return b, nil
}
func Check(ctx context.Context, tag string) (Release, error) {
	var out Release
	endpoint := "latest"
	if tag != "" {
		if _, e := Version(tag); e != nil {
			return out, e
		}
		endpoint = "tags/v" + strings.TrimPrefix(tag, "v")
	}
	b, e := read(ctx, API+endpoint, 2<<20)
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return out, errors.New("Invalid release metadata")
	}
	if _, e = Version(out.Tag); e != nil || out.Draft || out.Prerelease {
		return out, errors.New("Not a stable release")
	}
	if tag != "" && strings.TrimPrefix(out.Tag, "v") != strings.TrimPrefix(tag, "v") {
		return out, errors.New("Release version mismatch")
	}
	if out.URL != "https://github.com/XLYing23333/Weroxy/releases/tag/"+out.Tag {
		return out, errors.New("Unexpected release URL")
	}
	return out, nil
}
func (r Release) Asset(name string) (Asset, error) {
	var out Asset
	found := false
	for _, a := range r.Assets {
		if a.Name != name {
			continue
		}
		if found {
			return out, errors.New("Duplicate release asset")
		}
		out = a
		found = true
	}
	if !found {
		return out, errors.New("Required release asset is missing")
	}
	expected := DownloadPrefix + url.PathEscape(r.Tag) + "/" + url.PathEscape(name)
	if out.URL != expected || strings.ContainsAny(name, "/\\") || out.Size < 1 {
		return Asset{}, errors.New("Invalid release asset")
	}
	return out, nil
}
func (r Release) Hash(ctx context.Context, name string) (string, error) {
	a, e := r.Asset("SHA256SUMS")
	if e != nil {
		return "", e
	}
	if a.Size > 1<<20 {
		return "", errors.New("Checksum manifest too large")
	}
	b, e := read(ctx, a.URL, 1<<20)
	if e != nil {
		return "", e
	}
	result := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if len(line) < 67 || line[64:66] != "  " {
			return "", errors.New("Invalid checksum manifest")
		}
		hash, file := line[:64], line[66:]
		raw, e := hex.DecodeString(hash)
		if e != nil || len(raw) != 32 || seen[file] {
			return "", errors.New("Invalid checksum manifest")
		}
		seen[file] = true
		if file == name {
			result = hash
		}
	}
	if result == "" {
		return "", errors.New("Asset checksum missing")
	}
	return result, nil
}
func (r Release) Download(ctx context.Context, name, dir string, limit int64) (path, hash string, err error) {
	a, e := r.Asset(name)
	if e != nil {
		return "", "", e
	}
	if a.Size > limit {
		return "", "", errors.New("Release asset too large")
	}
	hash, e = r.Hash(ctx, name)
	if e != nil {
		return "", "", e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, e := request(ctx, client(10*time.Minute), a.URL)
	if e != nil {
		return "", "", e
	}
	defer res.Body.Close()
	f, e := os.CreateTemp(dir, "weroxy-download-*")
	if e != nil {
		return "", "", e
	}
	path = f.Name()
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(path)
		}
	}()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, limit+1))
	if e != nil {
		return path, hash, e
	}
	if n != a.Size || n > limit || hex.EncodeToString(h.Sum(nil)) != hash {
		return path, hash, errors.New("Release SHA-256 or size mismatch")
	}
	err = f.Sync()
	return
}

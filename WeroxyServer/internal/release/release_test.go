package release

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestStableVersionsAndAssetIdentity(t *testing.T) {
	for _, s := range []string{"v0.5.0", "1.20.3"} {
		if _, e := Version(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"0.5", "v01.2.3", "0.5.0-rc1", "99999999999999999999999.0.0"} {
		if _, e := Version(s); e == nil {
			t.Fatal("invalid accepted", s)
		}
	}
	if !Newer("v0.10.0", "0.9.9") || Newer("v0.4.0", "0.5.0") || Newer("0.5.0", "0.5.0") {
		t.Fatal("version ordering")
	}
	r := Release{Tag: "v0.5.0", Assets: []Asset{{Name: "a.deb", URL: DownloadPrefix + "v0.5.0/a.deb", Size: 3}}}
	if _, e := r.Asset("a.deb"); e != nil {
		t.Fatal(e)
	}
	r.Assets[0].URL = "https://example.com/a.deb"
	if _, e := r.Asset("a.deb"); e == nil {
		t.Fatal("external asset accepted")
	}
}
func TestVerifiedDownloadRejectsTamperingAndCleansPartialFile(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	body := "verified-package"
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	r := Release{Tag: "v0.5.0", Assets: []Asset{{Name: "a.deb", URL: DownloadPrefix + "v0.5.0/a.deb", Size: int64(len(body))}, {Name: "SHA256SUMS", URL: DownloadPrefix + "v0.5.0/SHA256SUMS", Size: 80}}}
	http.DefaultTransport = transport(func(req *http.Request) (*http.Response, error) {
		text := body
		if strings.HasSuffix(req.URL.Path, "SHA256SUMS") {
			text = sum + "  a.deb\n"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text)), Header: make(http.Header)}, nil
	})
	dir := t.TempDir()
	p, _, e := r.Download(context.Background(), "a.deb", dir, 128)
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(p)
	body = "tampered-package"
	if _, _, e = r.Download(context.Background(), "a.deb", dir, 128); e == nil {
		t.Fatal("tamper accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("partial file left behind")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Metadata limits and manifest parsing are independent from package size.
	r.Assets[1].Size = 2 << 20
	if _, e = r.Hash(ctx, "a.deb"); e == nil {
		t.Fatal("oversized manifest accepted")
	}
}

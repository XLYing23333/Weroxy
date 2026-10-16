//go:build linux

package upgrade

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPackageTrustAndMetadata(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "dpkg-deb")
	writeMeta := func(name, arch string) {
		t.Helper()
		if e := os.WriteFile(tool, []byte("#!/bin/sh\nprintf '"+name+"\\n1.2.3\\n"+arch+"\\n'\n"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("PATH", dir)
	writeMeta("weroxy-client", runtime.GOARCH)
	source := filepath.Join(dir, "candidate.deb")
	body := []byte("verified package input")
	if e := os.WriteFile(source, body, 0600); e != nil {
		t.Fatal(e)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	if _, e := verifyPackage(context.Background(), source, hash, filepath.Join(dir, "good.deb"), ".deb"); e != nil {
		t.Fatal(e)
	}
	if _, e := verifyPackage(context.Background(), source, fmt.Sprintf("%064d", 0), filepath.Join(dir, "wrong.deb"), ".deb"); e == nil {
		t.Fatal("wrong hash accepted")
	}
	link := filepath.Join(dir, "link.deb")
	if e := os.Symlink(source, link); e != nil {
		t.Fatal(e)
	}
	if _, e := verifyPackage(context.Background(), link, hash, filepath.Join(dir, "symlink.deb"), ".deb"); e == nil {
		t.Fatal("symlink accepted")
	}
	for _, v := range []struct{ name, arch string }{{"other", runtime.GOARCH}, {"weroxy-client", "wrong"}} {
		writeMeta(v.name, v.arch)
		if _, e := readPackageInfo(context.Background(), source, ".deb", false); e == nil {
			t.Fatal("foreign package accepted")
		}
	}
	if packageFormat("client.tar.gz") != "" || packageFormat("client.zip") != "" {
		t.Fatal("portable archive accepted")
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"weroxy/client/internal/buildinfo"
	"weroxy/client/internal/release"
)

type updateTransport func(*http.Request) (*http.Response, error)

func (f updateTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdateCancellationAndBadDownloadDoNotReachInstallation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native update path is Linux only")
	}
	for _, scenario := range []string{"cancel", "wrong_architecture", "bad_checksum", "request_cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			beforeVersion, beforeTransport, beforeInput := buildinfo.Version, http.DefaultTransport, commandStdin
			t.Cleanup(func() {
				buildinfo.Version = beforeVersion
				http.DefaultTransport = beforeTransport
				commandStdin = beforeInput
			})
			buildinfo.Version = "0.5.0"
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "dpkg-query"), []byte("#!/bin/sh\nprintf 0.5.0\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			commandStdin = strings.NewReader("n\n")
			if scenario == "bad_checksum" {
				commandStdin = strings.NewReader("y\n")
			}
			name := clientAsset("0.6.0", ".deb")
			assetName := name
			if scenario == "wrong_architecture" {
				assetName = "unsupported.deb"
			}
			r := release.Release{Tag: "v0.6.0", URL: "https://github.com/XLYing23333/Weroxy/releases/tag/v0.6.0", Assets: []release.Asset{{Name: assetName, URL: release.DownloadPrefix + "v0.6.0/" + assetName, Size: 3}, {Name: "SHA256SUMS", URL: release.DownloadPrefix + "v0.6.0/SHA256SUMS", Size: 100}}}
			metadata, _ := json.Marshal(r)
			calls := []string{}
			http.DefaultTransport = updateTransport(func(req *http.Request) (*http.Response, error) {
				calls = append(calls, req.URL.String())
				if err := req.Context().Err(); err != nil {
					return nil, err
				}
				body := string(metadata)
				if strings.HasSuffix(req.URL.Path, "SHA256SUMS") {
					body = strings.Repeat("0", 64) + "  " + name + "\n"
				} else if strings.HasSuffix(req.URL.Path, ".deb") {
					body = "bad"
				} else if req.URL.String() != release.API+"latest" {
					return nil, fmt.Errorf("unexpected request")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "request_cancelled" {
				cancel()
			}
			err := updateClient(ctx)
			if scenario == "cancel" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe update accepted")
			}
			if scenario != "bad_checksum" && len(calls) > 1 {
				t.Fatal("download reached before valid confirmation and platform check")
			}
			if scenario == "bad_checksum" && len(calls) != 3 {
				t.Fatalf("unexpected network stages: %d", len(calls))
			}
			files, _ := os.ReadDir(temp)
			if len(files) != 0 {
				t.Fatal("unverified package left behind")
			}
		})
	}
}

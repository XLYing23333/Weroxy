package cli

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// healthCommand checks only a loopback management listener and never follows
// redirects, uses proxies or uses TLS.
func healthCommand(args []string, opt Option) int {
	raw, err := flagValue(args, "url", "http://127.0.0.1:9415")
	if err != nil {
		fmt.Fprintln(opt.Stderr, "invalid health arguments")
		return 2
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Scheme != "http" {
		fmt.Fprintln(opt.Stderr, "health requires a loopback HTTP base URL")
		return 2
	}
	ip := net.ParseIP(endpoint.Hostname())
	if ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(opt.Stderr, "health requires a loopback HTTP base URL")
		return 2
	}
	mode, err := flagValue(args, "check", "live")
	if err != nil || mode != "live" && mode != "ready" {
		fmt.Fprintln(opt.Stderr, "check must be live or ready")
		return 2
	}
	endpoint.Path = "/healthz"
	if mode == "ready" {
		endpoint.Path = "/readyz"
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, ResponseHeaderTimeout: 2 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(endpoint.String())
	if err != nil {
		fmt.Fprintln(opt.Stderr, "health check failed")
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		fmt.Fprintln(opt.Stderr, "health check failed")
		return 1
	}
	fmt.Fprintln(opt.Stdout, "ok")
	return 0
}

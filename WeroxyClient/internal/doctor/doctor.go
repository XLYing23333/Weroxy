// Package doctor performs bounded, read-only connectivity diagnostics.
package doctor

import (
	"context"

	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"weroxy/client/internal/config"
	"weroxy/client/internal/harden"
	wp "weroxy/client/internal/protocol/weroxy"
	"weroxy/client/internal/secure"
)

// Check never contains a credential, address, certificate contents or raw network error.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Report is safe to print or attach to a diagnostic bundle.
type Report struct {
	Checks    []Check        `json:"checks"`
	OK        bool           `json:"ok"`
	Hardening []harden.Check `json:"hardening"`
}

func Run(parent context.Context, cfg config.Config) Report {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	report := Report{OK: true, Hardening: harden.Inspect(ctx)}
	add := func(name, status, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			report.OK = false
		}
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		add("dns", "fail", "Invalid Server address")
		return report
	}
	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		add("dns", "fail", "Unable to resolve Server name")
		return report
	}
	add("dns", "pass", "Server name resolved")
	dial := func(addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	conn, err := dial(cfg.Server)
	if err != nil {
		add("control_port", "fail", "Control port connection failed; check Host, Control Port, container port publication and firewall")
		return report
	}
	defer conn.Close()
	add("control_port", "pass", "Control port TCP connection established")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	token, err := config.ReadToken(strings.NewReader(cfg.Key))
	if err != nil {
		add("auth", "fail", "Invalid device credential format")
		return report
	}
	defer func() {
		for i := range token {
			token[i] = 0
		}
	}()
	credential := secure.Derive(token, "control")
	encrypted, _, err := secure.Client(conn, 'C', credential.ID[:], credential.PSK, nil, nil)
	if err != nil {
		add("auth", "fail", "Secure handshake failed; check both endpoint versions and Key")
		return report
	}
	conn = encrypted
	reader := wp.Reader{R: conn}
	add("transport", "pass", "Control and binding protected; business traffic retains its original protocol")
	if err := write(conn, wp.TypeDiagnose, 2, cfg.DeviceID); err != nil {
		add("auth", "fail", "Unable to send diagnostic request")
		return report
	}
	var frame wp.Frame
	frame, err = reader.Next()
	if err != nil {
		add("auth", "fail", "Unable to read diagnostic response")
		return report
	}
	if frame.Type == wp.TypeError {
		add("auth", "fail", "Device credential rejected or disabled; check Key, device status and Client version in Server Web")
		return report
	}
	if frame.Type != wp.TypeDiagnose {
		add("auth", "fail", "Server does not support the diagnostic protocol")
		return report
	}
	parts, err := wp.Strings(frame.Body, 2)
	if err != nil {
		add("auth", "fail", "Invalid diagnostic response format")
		return report
	}
	add("auth", "pass", "Device credential valid; running control connection was not replaced")
	serverTime, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		add("time", "fail", "Invalid Server time format")
	} else {
		skew := time.Since(serverTime)
		if skew < 0 {
			skew = -skew
		}
		if skew > 2*time.Minute {
			add("time", "fail", "Clock difference exceeds two minutes")
		} else {
			add("time", "pass", "Clock difference is within two minutes")
		}
	}
	if parts[1] == "" {
		add("data_ports", "skip", "No data port is currently serving this device")
	} else {
		ports := strings.Split(parts[1], ",")
		if len(ports) > 200 {
			add("data_ports", "fail", "Server returned too many data ports")
		} else {
			failed := 0
			for _, port := range ports {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					failed++
					continue
				}
				if ctx.Err() != nil {
					failed++
					continue
				}
				data, err := dial(net.JoinHostPort(host, port))
				if err != nil {
					failed++
				} else {
					_ = data.Close()
				}
			}
			if failed > 0 {
				add("data_ports", "fail", strconv.Itoa(failed)+" assigned data port(s) unreachable")
			} else {
				add("data_ports", "pass", strconv.Itoa(len(ports))+" assigned data port(s) reachable")
			}
		}
	}
	add("targets", "skip", "Targets are configured in Server Web; target reachability is checked when a forward is established")
	return report
}

func write(conn net.Conn, kind byte, id uint64, fields ...string) error {
	body, err := wp.PutStrings(fields...)
	if err != nil {
		return err
	}
	frame, err := wp.Encode(wp.Frame{Type: kind, RequestID: id, Body: body})
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write")
		}
		frame = frame[n:]
	}
	return nil
}

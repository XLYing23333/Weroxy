package webui

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Publication is advisory Docker host binding evidence. It does not prove
// firewall rules or internet reachability, and never changes runtime state.
type Publication struct {
	PortStatus     map[int]string `json:"-"`
	Status         string         `json:"status"`
	CheckedAt      string         `json:"checked_at,omitempty"`
	ListenerCount  int            `json:"listener_count"`
	PublishedCount int            `json:"published_count"`
	MissingPorts   []int          `json:"missing_ports"`
	LoopbackOnly   bool           `json:"loopback_only"`
}

type publicationFile struct {
	ContainerID string `json:"container_id"`
	CheckedAt   string `json:"checked_at"`
	Ports       []struct {
		ContainerPort int    `json:"container_port"`
		HostIP        string `json:"host_ip"`
		HostPort      int    `json:"host_port"`
	} `json:"ports"`
}

func publicationStatus(dataDir string) Publication {
	out := Publication{Status: "unverified", MissingPorts: []int{}}
	live := listeningTCPPorts()
	out.ListenerCount = len(live)
	if dataDir == "" || len(live) == 0 {
		return out
	}
	path := filepath.Join(dataDir, "deployment-publication.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return out
	}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()
	var snap publicationFile
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snap) != nil || len(snap.Ports) > 1024 {
		return out
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return out
	}
	hostname, err := os.Hostname()
	if err != nil || len(hostname) < 12 || !strings.HasPrefix(snap.ContainerID, hostname) {
		return out
	}
	checked, err := time.Parse(time.RFC3339Nano, snap.CheckedAt)
	if err != nil || checked.After(time.Now().Add(time.Minute)) {
		return out
	}
	out.CheckedAt = snap.CheckedAt
	if time.Since(checked) > 2*time.Minute {
		out.Status = "stale"
		return out
	}
	published := map[int]bool{}
	portStatus := map[int]string{}
	allLoopback := true
	for _, item := range snap.Ports {
		if item.ContainerPort < 1 || item.ContainerPort > 65535 || item.HostPort < 1 || item.HostPort > 65535 {
			return Publication{Status: "unverified", MissingPorts: []int{}}
		}
		ip := net.ParseIP(item.HostIP)
		if ip == nil {
			return Publication{Status: "unverified", MissingPorts: []int{}}
		}
		if !ip.IsLoopback() {
			allLoopback = false
		}
		published[item.ContainerPort] = true
		value := "published"
		if item.HostPort != item.ContainerPort {
			value = "remapped"
		} else if ip.IsLoopback() {
			value = "loopback_only"
		}
		if portStatus[item.ContainerPort] != "published" {
			portStatus[item.ContainerPort] = value
		}
	}
	out.PortStatus = portStatus
	out.LoopbackOnly = allLoopback && len(published) > 0
	for port := range live {
		if published[port] {
			out.PublishedCount++
		} else {
			out.MissingPorts = append(out.MissingPorts, port)
		}
	}
	sort.Ints(out.MissingPorts)
	if len(out.MissingPorts) > 0 {
		out.Status = "partial"
	} else {
		out.Status = "published"
	}
	return out
}

// listeningTCPPorts observes LISTEN sockets in the container's network
// namespace. It intentionally does not mistake a bound socket for host publish.
func listeningTCPPorts() map[int]bool {
	out := map[int]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			rawHost, rawPort, ok := strings.Cut(fields[1], ":")
			if !ok || len(rawHost) == 8 && strings.HasSuffix(rawHost, "7F") || rawHost == "00000000000000000000000001000000" {
				continue
			}
			port, err := strconv.ParseUint(rawPort, 16, 16)
			if err == nil && port > 0 {
				out[int(port)] = true
			}
		}
		file.Close()
	}
	return out
}

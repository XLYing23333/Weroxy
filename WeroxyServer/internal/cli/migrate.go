package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"weroxy/server/internal/legacy"
	"weroxy/server/internal/storage/sqlite"
)

type sourceClient struct {
	Name          string       `json:"name"`
	ClientKey     importSecret `json:"clientKey"`
	ProxyMappings []struct {
		Name     string `json:"name"`
		InetPort *int   `json:"inetPort"`
		Lan      string `json:"lan"`
	} `json:"proxyMappings"`
}

func migrateCommand(args []string, opt Option) int {
	if len(args) == 0 || args[0] != "lanproxy" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server migrate lanproxy --file <config.json> --data <dir> --bind-host <ip> [--allow-ports <port,first-last>] --dry-run|--apply")
		return 2
	}
	args = args[1:]
	dry, apply := false, false
	for _, arg := range args {
		if arg == "--dry-run" {
			dry = true
		}
		if arg == "--apply" {
			apply = true
		}
	}
	if dry == apply {
		fmt.Fprintln(opt.Stderr, "choose exactly one of --dry-run or --apply")
		return 2
	}
	file, err := flagValue(args, "file", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	data, err := flagValue(args, "data", "/data")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	bind, err := flagValue(args, "bind-host", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	if file == "" || net.ParseIP(bind) == nil {
		fmt.Fprintln(opt.Stderr, "a source file and explicit IP bind host are required")
		return 2
	}
	bind = net.ParseIP(bind).String()
	allowedRaw, err := flagValue(args, "allow-ports", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, "invalid allowed port ranges")
		return 2
	}
	allowedPorts, err := parseImportPortRanges(allowedRaw)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "invalid allowed port ranges; use port,first-last")
		return 2
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8<<20 {
		fmt.Fprintln(opt.Stderr, "invalid import file")
		return 2
	}
	input, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot read import file")
		return 2
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > 8<<20 {
		fmt.Fprintln(opt.Stderr, "invalid import file")
		return 2
	}
	body, err := io.ReadAll(io.LimitReader(input, (8<<20)+1))
	defer zero(body)
	_ = input.Close()
	if err != nil || len(body) > 8<<20 {
		fmt.Fprintln(opt.Stderr, "cannot read import file")
		return 2
	}
	var source []sourceClient
	defer func() {
		for i := range source {
			zero(source[i].ClientKey)
			source[i].ClientKey = nil
		}
	}()
	if err := json.Unmarshal(body, &source); err != nil || source == nil {
		fmt.Fprintln(opt.Stderr, "expected a top-level Client array")
		return 2
	}
	zero(body)
	body = nil
	if len(source) > 4096 {
		fmt.Fprintf(opt.Stdout, "ISSUE client_preflight_budget required=%d capacity=4096\n", len(source))
		return 2
	}
	mappingCount := 0
	for _, client := range source {
		mappingCount += len(client.ProxyMappings)
		if mappingCount > 16384 {
			fmt.Fprintf(opt.Stdout, "ISSUE mapping_preflight_budget required=%d capacity=16384\n", mappingCount)
			return 2
		}
	}
	if dry {
		if _, err := os.Stat(filepath.Join(data, "weroxy.db")); err != nil {
			fmt.Fprintln(opt.Stderr, "dry-run requires an initialized Weroxy data directory")
			return 2
		}
	}
	items := make([]sqlite.LegacyImport, 0, len(source))
	clearItems := func() {
		for i := range items {
			zero(items[i].Key)
			zero(items[i].MAC)
			items[i].Key = nil
			items[i].MAC = nil
		}
	}
	defer clearItems()
	var validation []sqlite.ImportIssue
	names, keys, usedPorts := map[string]bool{}, map[[32]byte]bool{}, map[int]bool{}
	for clientIndex, client := range source {
		index := clientIndex + 1
		before := len(validation)
		if !validUsername(client.Name) {
			validation = append(validation, sqlite.ImportIssue{ClientIndex: index, Device: client.Name, Code: "invalid_name"})
		} else if names[client.Name] {
			validation = append(validation, sqlite.ImportIssue{ClientIndex: index, Device: client.Name, Code: "duplicate_name"})
		} else {
			names[client.Name] = true
		}
		keyIssue := ""
		switch {
		case len(client.ClientKey) == 0:
			keyIssue = "empty_key"
		case len(client.ClientKey) > 127:
			keyIssue = "uri_too_long"
		case !utf8.Valid(client.ClientKey) || bytes.IndexFunc(client.ClientKey, unicode.IsControl) >= 0:
			keyIssue = "invalid_key"
		}
		if keyIssue != "" {
			validation = append(validation, sqlite.ImportIssue{ClientIndex: index, Device: client.Name, Code: keyIssue})
		} else if keys[sha256.Sum256(client.ClientKey)] {
			validation = append(validation, sqlite.ImportIssue{ClientIndex: index, Device: client.Name, Code: "duplicate_key"})
		} else {
			keys[sha256.Sum256(client.ClientKey)] = true
		}
		item := sqlite.LegacyImport{Name: client.Name, Key: client.ClientKey, SourceIndex: index}
		for mappingIndex, mapping := range client.ProxyMappings {
			position := mappingIndex + 1
			validPort := mapping.InetPort != nil && *mapping.InetPort >= 1 && *mapping.InetPort <= 65535
			listen := ""
			if validPort {
				listen = net.JoinHostPort(bind, strconv.Itoa(*mapping.InetPort))
			}
			issue := func(code string) {
				validation = append(validation, sqlite.ImportIssue{ClientIndex: index, MappingIndex: position, Device: client.Name, Listen: listen, Code: code})
			}
			duplicatePort := false
			if !validPort {
				issue("invalid_port")
			} else if usedPorts[*mapping.InetPort] {
				duplicatePort = true
				issue("duplicate_port")
			} else {
				usedPorts[*mapping.InetPort] = true
			}
			validTarget := validLegacyTarget(mapping.Lan)
			if !validTarget {
				issue("invalid_target")
			}
			if validPort && !duplicatePort && validTarget {
				item.Forwards = append(item.Forwards, sqlite.LegacyImportForward{Listen: listen, Target: mapping.Lan, SourceIndex: position, AllowOutsidePool: allowedPorts[*mapping.InetPort]})
			}
		}
		if len(validation) == before {
			items = append(items, item)
		} else {
			zero(client.ClientKey)
		}
	}
	clear(keys)
	keys = nil
	source = nil
	for _, issue := range validation {
		printImportIssue(opt.Stdout, issue)
	}
	if len(validation) != 0 {
		return 1
	}
	secret, err := legacy.LoadSecret(data, apply)
	if errors.Is(err, os.ErrNotExist) && dry {
		secret = make([]byte, 32)
		_, err = rand.Read(secret)
	}
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot load local credential index secret")
		return 1
	}
	defer zero(secret)
	for i := range items {
		items[i].MAC = legacy.MAC(secret, items[i].Key)
	}
	var db *sqlite.DB
	var cleanup func()
	if dry {
		db, cleanup, err = sqlite.OpenPreview(filepath.Join(data, "weroxy.db"))
	} else {
		db, err = sqlite.Open(filepath.Join(data, "weroxy.db"), sqlite.DefaultQueue)
	}
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot open Weroxy database")
		return 1
	}
	if cleanup != nil {
		defer cleanup()
	}
	defer db.Close()
	// A preview commits only to the temporary snapshot; the source is read only.
	issues, err := db.ImportLegacy(context.Background(), items, true)
	clearItems()
	zero(secret)
	for _, issue := range issues {
		printImportIssue(opt.Stdout, issue)
	}
	if err != nil || len(issues) != 0 {
		if err != nil && len(issues) == 0 {
			fmt.Fprintln(opt.Stderr, "import transaction failed; inspect destination before retry")
		}
		return 1
	}
	pool, err := db.PortPool(context.Background())
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot read destination port capacity")
		return 1
	}
	ordered := make([]int, 0, len(usedPorts))
	for port := range usedPorts {
		ordered = append(ordered, port)
	}
	sort.Ints(ordered)
	for _, port := range ordered {
		if !pool.Enabled || port < pool.ForwardFirst || port > pool.ForwardLast {
			fmt.Fprintf(opt.Stdout, "DEPLOY_PORT %d\n", port)
			fmt.Fprintf(opt.Stdout, "DEPLOY_BIND %q docker_publish=%q\n", net.JoinHostPort(bind, strconv.Itoa(port)), strconv.Itoa(port)+":"+strconv.Itoa(port)+"/tcp")
		}
		address := net.JoinHostPort(bind, strconv.Itoa(port))
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			// The old Server may still own this port before cutover. Preserve
			// its configuration and report the conflict without failing import.
			fmt.Fprintf(opt.Stdout, "HOST_PORT_IN_USE %d\n", port)
		} else {
			_ = listener.Close()
		}
	}
	mode := "PREVIEW"
	if apply {
		mode = "IMPORTED"
	}
	fmt.Fprintf(opt.Stdout, "%s devices=%d forwards=%d; verify host-published ports before cutover\n", mode, len(items), len(usedPorts))
	return 0
}

// validLegacyTarget keeps the original host:port while refusing addresses that
// would fail a TCP dial or inject controls into diagnostics.
func validLegacyTarget(target string) bool {
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, "\r\n\t /\\") {
		return false
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return false
	}
	numeric := true
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r > 127 || (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
			if r < '0' || r > '9' {
				numeric = false
			}
		}
	}
	return !numeric || !strings.Contains(name, ".")
}

func printImportIssue(out io.Writer, issue sqlite.ImportIssue) {
	fmt.Fprintf(out, "ISSUE %s client=%d mapping=%d listen=%q", issue.Code, issue.ClientIndex, issue.MappingIndex, issue.Listen)
	if issue.Capacity > 0 {
		fmt.Fprintf(out, " required=%d capacity=%d", issue.Required, issue.Capacity)
	}
	fmt.Fprintln(out)
}

// Ranges only authorize exact source bindings recorded by the transaction.
// Unused ports in an approved span do not become future allocation space.
func parseImportPortRanges(raw string) (map[int]bool, error) {
	out := make(map[int]bool)
	if raw == "" {
		return out, nil
	}
	if len(raw) > 1024 {
		return nil, errors.New("port ranges too long")
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		var first, last int
		var err error
		if strings.Contains(part, "-") {
			first, last, err = parseSpan(part)
		} else {
			first, err = strconv.Atoi(part)
			last = first
		}
		if err != nil || first < 1 || last < first || last > 65535 {
			return nil, errors.New("invalid port range")
		}
		for port := first; port <= last; port++ {
			out[port] = true
		}
	}
	return out, nil
}

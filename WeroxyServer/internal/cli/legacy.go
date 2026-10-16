package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"weroxy/server/internal/legacy"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/server"
	"weroxy/server/internal/storage/sqlite"
)

func legacyCommand(args []string, opt Option) int {
	if len(args) < 2 {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server legacy device add | legacy forward add")
		return 2
	}
	switch args[0] + " " + args[1] {
	case "device add":
		return addLegacyDevice(args[2:], opt)
	case "forward add":
		return addLegacyForward(args[2:], opt)
	default:
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server legacy device add | legacy forward add")
		return 2
	}
}

func addLegacyDevice(args []string, opt Option) int {
	data, name, keyPath, err := legacyDeviceFlags(args)
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	if !validUsername(name) {
		fmt.Fprintln(opt.Stderr, "Invalid device name.")
		return 2
	}
	key, err := readKeyFile(keyPath)
	if err != nil {
		fmt.Fprintln(opt.Stderr, keyError(err))
		return 2
	}
	defer zero(key)
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	secret, err := legacy.LoadSecret(data, true)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "Unable to prepare the local verification secret.")
		return 1
	}
	mac := legacy.MAC(secret, key)
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	ctx := context.Background()
	if err := db.AddLegacyDevice(ctx, name, mac, string(key)); err != nil {
		fmt.Fprintln(opt.Stderr, legacyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(ctx, "legacy_device_add", "success", name)
	log.Info("legacy device added", map[string]string{"device": name})
	fmt.Fprintln(opt.Stdout, "Legacy device added.")
	return 0
}

func addLegacyForward(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	device, err := flagValue(args, "device", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	listen, err := flagValue(args, "listen", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	target, err := flagValue(args, "target", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	if data == "" || device == "" || listen == "" || target == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server legacy forward add --data <dir> --device <name> --listen <host:port> --target <host:port>")
		return 2
	}
	listen, err = canonicalAddr(listen)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "Invalid listener address.")
		return 2
	}
	target, err = canonicalAddr(target)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "Invalid target address.")
		return 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	ctx := context.Background()
	if err := db.AddLegacyForward(ctx, device, listen, target); err != nil {
		fmt.Fprintln(opt.Stderr, legacyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(ctx, "legacy_forward_add", "success", device)
	log.Info("legacy forward added", map[string]string{"device": device, "listen": listen})
	fmt.Fprintln(opt.Stdout, "Legacy forward added.")
	return 0
}

func legacyDeviceFlags(args []string) (data, name, keyPath string, err error) {
	data, err = flagValue(args, "data", "")
	if err != nil {
		return "", "", "", err
	}
	name, err = flagValue(args, "name", "")
	if err != nil {
		return "", "", "", err
	}
	keyPath, err = flagValue(args, "key-file", "")
	if err != nil {
		return "", "", "", err
	}
	if data == "" || name == "" || keyPath == "" {
		return "", "", "", errors.New("usage: weroxy-Server legacy device add --data <dir> --name <name> --key-file <file>")
	}
	return data, name, keyPath, nil
}

func openLegacyDB(data string, opt Option) (*sqlite.DB, *logging.Logger, int) {
	log := logging.New(logging.Options{Dir: filepath.Join(data, "logs"), Err: opt.Stderr})
	db, err := sqlite.Open(filepath.Join(data, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		log.Close()
		fmt.Fprintln(opt.Stderr, err.Error())
		return nil, nil, 1
	}
	return db, log, 0
}

func readKeyFile(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 && body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
		if len(body) > 0 && body[len(body)-1] == '\r' {
			body = body[:len(body)-1]
		}
	}
	if len(body) == 0 {
		return nil, errEmptyKey
	}
	if len(body) > 127 {
		return nil, errLongKey
	}
	return body, nil
}

var (
	errEmptyKey = errors.New("empty client key")
	errLongKey  = errors.New("client key longer than 127 bytes")
)

func keyError(err error) string {
	switch {
	case errors.Is(err, errEmptyKey):
		return "Client Key is empty; nothing saved."
	case errors.Is(err, errLongKey):
		return "Client Key exceeds the Legacy URI limit of 127 bytes; nothing saved."
	default:
		return "Unable to read the Client Key file."
	}
}

func legacyStoreError(err error) string {
	switch {
	case errors.Is(err, sqlite.ErrLegacyExists):
		return "Device or Client Key already exists; nothing saved."
	case errors.Is(err, sqlite.ErrLegacyNotFound):
		return "Device not found."
	case errors.Is(err, sqlite.ErrLegacyListen):
		return "Listener address is occupied."
	case errors.Is(err, sqlite.ErrPortRange):
		return "Port is outside the forwarding pool or reserved listener permissions; configure an explicit pool or allowed migration ports."
	case errors.Is(err, sqlite.ErrPortConflict):
		return "Listener conflicts with an existing port."
	default:
		return "Unable to save Legacy configuration."
	}
}

func canonicalAddr(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", errors.New("invalid address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

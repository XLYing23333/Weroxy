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
		fmt.Fprintln(opt.Stderr, "设备名无效。")
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
		fmt.Fprintln(opt.Stderr, "未能准备本机校验密钥。")
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
	fmt.Fprintln(opt.Stdout, "已添加旧客户端设备。")
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
		fmt.Fprintln(opt.Stderr, "监听地址无效。")
		return 2
	}
	target, err = canonicalAddr(target)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "目标地址无效。")
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
	fmt.Fprintln(opt.Stdout, "已添加旧客户端转发。")
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
		return "Client Key 为空，未保存。"
	case errors.Is(err, errLongKey):
		return "Client Key 超过 127 字节，旧客户端无法在一帧 URI 中发送，未保存。"
	default:
		return "未能读取 Client Key 文件。"
	}
}

func legacyStoreError(err error) string {
	switch {
	case errors.Is(err, sqlite.ErrLegacyExists):
		return "设备或 Client Key 已存在，未保存。"
	case errors.Is(err, sqlite.ErrLegacyNotFound):
		return "设备不存在。"
	case errors.Is(err, sqlite.ErrLegacyListen):
		return "监听地址已被占用。"
	case errors.Is(err, sqlite.ErrPortRange):
		return "端口不在转发池或已保留的监听许可中，请明确配置转发池或迁移允许端口。"
	case errors.Is(err, sqlite.ErrPortConflict):
		return "监听地址与已有端口冲突。"
	default:
		return "未能保存旧客户端配置。"
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

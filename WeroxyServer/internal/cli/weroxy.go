package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"weroxy/server/internal/legacy"
	"weroxy/server/internal/server"
	"weroxy/server/internal/storage/sqlite"
)

func weroxyCommand(args []string, opt Option) int {
	if len(args) < 2 {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy device add | weroxy forward add | weroxy device revoke")
		return 2
	}
	switch args[0] + " " + args[1] {
	case "device add":
		return addWeroxyDevice(args[2:], opt)
	case "device rotate":
		return rotateWeroxyDevice(args[2:], opt)
	case "device limit":
		return limitWeroxyDevice(args[2:], opt)
	case "device revoke":
		return revokeWeroxyDevice(args[2:], opt)
	case "forward add":
		return addWeroxyForward(args[2:], opt)
	case "forward shrink":
		return shrinkWeroxyForward(args[2:], opt)
	case "pool set":
		return setWeroxyPool(args[2:], opt)
	case "policy set":
		return setWeroxyPolicy(args[2:], opt)
	case "ban add":
		return addWeroxyRule(args[2:], opt, "ban")
	case "allow add":
		return addWeroxyRule(args[2:], opt, "allow")
	case "capacity show":
		return showWeroxyCapacity(args[2:], opt)
	default:
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy device add | weroxy forward add | weroxy device revoke | weroxy pool set | weroxy policy set | weroxy capacity show")
		return 2
	}
}

func addWeroxyDevice(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	name, err := flagValue(args, "name", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	if data == "" || name == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy device add --data <dir> --name <name>")
		return 2
	}
	if !validUsername(name) {
		fmt.Fprintln(opt.Stderr, "设备名无效。")
		return 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 1
	}
	secret, err := legacy.LoadSecret(data, true)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "未能准备本机校验密钥。")
		return 1
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		fmt.Fprintln(opt.Stderr, "未能生成 Token。")
		return 1
	}
	var uidRaw [16]byte
	if _, err := rand.Read(uidRaw[:]); err != nil {
		fmt.Fprintln(opt.Stderr, "未能生成设备 ID。")
		return 1
	}
	token := hex.EncodeToString(raw[:])
	uid := hex.EncodeToString(uidRaw[:])
	mac := legacy.MAC(secret, raw[:])
	for i := range raw {
		raw[i] = 0
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	ctx := context.Background()
	if err := db.AddWeroxyDevice(ctx, name, uid, mac, token); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(ctx, "weroxy_device_add", "success", name)
	log.Info("weroxy device added", map[string]string{"device": name})
	fmt.Fprintf(opt.Stdout, "device_id: %s\ntoken: %s\n管理页可以再次查看并复制这个 token。\n", uid, token)
	return 0
}

func addWeroxyForward(args []string, opt Option) int {
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
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy forward add --data <dir> --device <name> --listen <host:port> --target <host:port>")
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
	mode, err := flagValue(args, "mode", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	minPorts, preferred, maxPorts := 0, 0, 0
	if flagPresent(args, "min") || flagPresent(args, "preferred") || flagPresent(args, "max") {
		minPorts, preferred, maxPorts = 1, 1, 4
		if flagPresent(args, "min") {
			minPorts, err = requiredInt(args, "min")
		}
		if err == nil && flagPresent(args, "preferred") {
			preferred, err = requiredInt(args, "preferred")
		}
		if err == nil && flagPresent(args, "max") {
			maxPorts, err = requiredInt(args, "max")
		}
		if err != nil {
			fmt.Fprintln(opt.Stderr, "端口数量无效。")
			return 2
		}
	}
	if err := db.AddWeroxyForward(ctx, device, listen, target, mode, minPorts, preferred, maxPorts, flagPresent(args, "use-reserved"), flagPresent(args, "import")); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(ctx, "weroxy_forward_add", "success", device)
	log.Info("weroxy forward added", map[string]string{"device": device, "listen": listen})
	fmt.Fprintln(opt.Stdout, "已添加转发。")
	return 0
}

func revokeWeroxyDevice(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	name, err := flagValue(args, "name", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	if data == "" || name == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy device revoke --data <dir> --name <name>")
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
	if err := db.RevokeWeroxyDevice(ctx, name); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(ctx, "weroxy_device_revoke", "success", name)
	log.Info("weroxy device revoked", map[string]string{"device": name})
	fmt.Fprintln(opt.Stdout, "已吊销设备。正在运行的服务会在下一次检查时断开它的连接。")
	return 0
}

func weroxyStoreError(err error) string {
	switch {
	case errors.Is(err, sqlite.ErrWeroxyExists):
		return "设备已存在，未保存。"
	case errors.Is(err, sqlite.ErrWeroxyNotFound):
		return "设备不存在。"
	case errors.Is(err, sqlite.ErrWeroxyListen):
		return "监听地址已被占用。"
	case errors.Is(err, sqlite.ErrWeroxyRevoked):
		return "设备已吊销，不能添加转发。"
	case errors.Is(err, sqlite.ErrWeroxyLimit):
		return "这台设备已经有一条转发。"
	case errors.Is(err, sqlite.ErrPortConflict):
		return "监听地址与已有端口冲突。"
	case errors.Is(err, sqlite.ErrPortRange):
		return "端口范围或限额无效。"
	case errors.Is(err, sqlite.ErrPortQuota):
		return "数据端口额度不足，未保存这条转发。"
	case errors.Is(err, sqlite.ErrPolicyLooser):
		return "这条策略比上一级更松，未保存。"
	default:
		return "未能保存 Weroxy 配置。"
	}
}

// rotateWeroxyDevice emits the new random credential only on explicit invocation.
// Deployers must capture stdout into a protected pipe/file, as with device add.
func rotateWeroxyDevice(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil {
		return 2
	}
	name, err := flagValue(args, "name", "")
	if err != nil || data == "" || !validUsername(name) {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy device rotate --data <dir> --name <name>")
		return 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, "数据目录不可写。")
		return 1
	}
	secret, err := legacy.LoadSecret(data, false)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "无法读取本机校验密钥。")
		return 1
	}
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return 1
	}
	defer clear(raw[:])
	token := hex.EncodeToString(raw[:])
	mac := legacy.MAC(secret, raw[:])
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	if err := db.SetWeroxyToken(context.Background(), name, mac, token); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	_ = db.RecordAudit(context.Background(), "weroxy_device_rotate", "success", name)
	log.Info("weroxy device key rotated", map[string]string{"device": name})
	fmt.Fprintf(opt.Stdout, "token: %s\n", token)
	return 0
}

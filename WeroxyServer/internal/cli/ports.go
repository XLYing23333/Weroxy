package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"weroxy/server/internal/server"
	"weroxy/server/internal/storage/sqlite"
)

func limitWeroxyDevice(args []string, opt Option) int {
	data, name, code := namedData(args, opt, "usage: weroxy-Server weroxy device limit --data <dir> --name <name> --max-data-ports <n>")
	if code != 0 {
		return code
	}
	maxPorts, err := requiredInt(args, "max-data-ports")
	if err != nil {
		fmt.Fprintln(opt.Stderr, "设备端口上限无效。")
		return 2
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	if err := db.SetDeviceDataMax(context.Background(), name, maxPorts); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	fmt.Fprintln(opt.Stdout, "已更新设备数据端口上限。")
	return 0
}

func shrinkWeroxyForward(args []string, opt Option) int {
	data, device, listen, code := forwardRef(args, opt)
	if code != 0 {
		return code
	}
	maxPorts, err := requiredInt(args, "max")
	if err != nil {
		fmt.Fprintln(opt.Stderr, "端口数量无效。")
		return 2
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	if err := db.ShrinkForward(context.Background(), device, listen, maxPorts); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	fmt.Fprintln(opt.Stdout, "已缩小转发。仍在使用的连接会继续，新会话不再进入被排空的端口。")
	return 0
}

func setWeroxyPool(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil || data == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy pool set --data <dir> --forward-pool <first-last> --data-pool <first-last>")
		return 2
	}
	forward, err := flagValue(args, "forward-pool", "29000-29099")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	dataPool, err := flagValue(args, "data-pool", "29100-29199")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	reserved := 10
	if flagPresent(args, "reserved") {
		reserved, err = requiredInt(args, "reserved")
		if err != nil {
			fmt.Fprintln(opt.Stderr, "预留端口数量无效。")
			return 2
		}
	}
	bind, err := flagValue(args, "bind-host", "0.0.0.0")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return 2
	}
	forwardFirst, forwardLast, err := parseSpan(forward)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "转发端口范围无效。")
		return 2
	}
	dataFirst, dataLast, err := parseSpan(dataPool)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "数据端口范围无效。")
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
	if err := db.SetPortPool(context.Background(), sqlite.PortSettings{
		ForwardFirst: forwardFirst, ForwardLast: forwardLast,
		DataFirst: dataFirst, DataLast: dataLast, Reserved: reserved, BindHost: bind,
	}); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	fmt.Fprintln(opt.Stdout, "已启用端口池。")
	return 0
}

func setWeroxyPolicy(args []string, opt Option) int {
	data, scope, key, code := policyRef(args, opt)
	if code != 0 {
		return code
	}
	values := sqlite.PolicyValues{}
	var err error
	if values.MaxPending, err = optionalLimit(args, "max-pending"); err != nil {
		fmt.Fprintln(opt.Stderr, "限额无效。")
		return 2
	}
	if values.MaxPerIP, err = optionalLimit(args, "max-per-ip"); err != nil {
		fmt.Fprintln(opt.Stderr, "限额无效。")
		return 2
	}
	if values.RatePerSec, err = optionalLimit(args, "rate"); err != nil {
		fmt.Fprintln(opt.Stderr, "限额无效。")
		return 2
	}
	if values.Burst, err = optionalLimit(args, "burst"); err != nil {
		fmt.Fprintln(opt.Stderr, "限额无效。")
		return 2
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	if err := mutateLocalPolicy(db, func(ctx context.Context) error {
		return db.SetPolicy(ctx, scope, key, values)
	}); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	fmt.Fprintln(opt.Stdout, "已保存策略。")
	return 0
}

func addWeroxyRule(args []string, opt Option, action string) int {
	data, scope, key, code := policyRef(args, opt)
	if code != 0 {
		return code
	}
	cidr, err := flagValue(args, "cidr", "")
	if err != nil || cidr == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy ban add --data <dir> --scope global|device|forward --cidr <cidr>")
		return 2
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	if err := mutateLocalPolicy(db, func(ctx context.Context) error {
		return db.AddAccessRule(ctx, sqlite.AccessRule{Scope: scope, Key: key, Action: action, CIDR: cidr})
	}); err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	fmt.Fprintln(opt.Stdout, "已保存访问规则。")
	return 0
}

func showWeroxyCapacity(args []string, opt Option) int {
	data, err := flagValue(args, "data", "")
	if err != nil || data == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy capacity show --data <dir>")
		return 2
	}
	db, log, code := openLegacyDB(data, opt)
	if db == nil {
		return code
	}
	defer db.Close()
	defer log.Close()
	ctx := context.Background()
	_, views, err := db.Capacity(ctx)
	if err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	type row struct {
		ForwardID         int64    `json:"forward_id"`
		ConfiguredMax     *int     `json:"configured_max"`
		Current           *int     `json:"current"`
		AvailableMaxTotal *int     `json:"available_max_total"`
		CanGrowBy         *int     `json:"can_grow_by"`
		LimitingReasons   []string `json:"limiting_reasons"`
		Legacy            bool     `json:"legacy"`
	}
	out := make([]row, 0, len(views))
	for _, view := range views {
		configured, current, available, grow := view.ConfiguredMax, view.Current, view.AvailableMaxTotal, view.CanGrowBy
		out = append(out, row{
			ForwardID: view.ForwardID, ConfiguredMax: &configured, Current: &current,
			AvailableMaxTotal: &available, CanGrowBy: &grow, LimitingReasons: view.Reasons,
		})
	}
	_, legacyForwards, err := db.ListLegacy(ctx)
	if err != nil {
		fmt.Fprintln(opt.Stderr, weroxyStoreError(err))
		return 1
	}
	for _, forward := range legacyForwards {
		out = append(out, row{ForwardID: forward.ID, Legacy: true})
	}
	body, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "未能生成容量预览。")
		return 1
	}
	fmt.Fprintf(opt.Stdout, "%s\n", body)
	return 0
}

func namedData(args []string, opt Option, usage string) (string, string, int) {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", 2
	}
	name, err := flagValue(args, "name", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", 2
	}
	if data == "" || name == "" {
		fmt.Fprintln(opt.Stderr, usage)
		return "", "", 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", 1
	}
	return data, name, 0
}

func forwardRef(args []string, opt Option) (string, string, string, int) {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	device, err := flagValue(args, "device", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	listen, err := flagValue(args, "listen", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	if data == "" || device == "" || listen == "" {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy forward shrink --data <dir> --device <name> --listen <host:port> --max <n>")
		return "", "", "", 2
	}
	listen, err = canonicalAddr(listen)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "监听地址无效。")
		return "", "", "", 2
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 1
	}
	return data, device, listen, 0
}

func policyRef(args []string, opt Option) (string, string, string, int) {
	data, err := flagValue(args, "data", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	scope, err := flagValue(args, "scope", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	if data == "" || (scope != "global" && scope != "device" && scope != "forward") {
		fmt.Fprintln(opt.Stderr, "usage: weroxy-Server weroxy policy set --data <dir> --scope global|device|forward")
		return "", "", "", 2
	}
	device, err := flagValue(args, "device", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	listen, err := flagValue(args, "listen", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 2
	}
	key := ""
	switch scope {
	case "device":
		if device == "" {
			fmt.Fprintln(opt.Stderr, "设备策略需要 --device。")
			return "", "", "", 2
		}
		key = device
	case "forward":
		if device == "" || listen == "" {
			fmt.Fprintln(opt.Stderr, "转发策略需要 --device 和 --listen。")
			return "", "", "", 2
		}
		listen, err = canonicalAddr(listen)
		if err != nil {
			fmt.Fprintln(opt.Stderr, "监听地址无效。")
			return "", "", "", 2
		}
		key = sqlite.ForwardKey(device, listen)
	}
	if err := server.Writable(data); err != nil {
		fmt.Fprintln(opt.Stderr, err.Error())
		return "", "", "", 1
	}
	return data, scope, key, 0
}

func flagPresent(args []string, name string) bool {
	prefix := "--" + name
	for _, arg := range args {
		if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
			return true
		}
	}
	return false
}

func requiredInt(args []string, name string) (int, error) {
	raw, err := flagValue(args, name, "")
	if err != nil || raw == "" {
		return 0, fmt.Errorf("missing %s", name)
	}
	return strconv.Atoi(raw)
}

func optionalLimit(args []string, name string) (*int, error) {
	if !flagPresent(args, name) {
		return nil, nil
	}
	value, err := requiredInt(args, name)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func parseSpan(value string) (int, int, error) {
	firstRaw, lastRaw, ok := strings.Cut(value, "-")
	if !ok {
		return 0, 0, fmt.Errorf("span")
	}
	first, err := strconv.Atoi(firstRaw)
	if err != nil {
		return 0, 0, err
	}
	last, err := strconv.Atoi(lastRaw)
	if err != nil {
		return 0, 0, err
	}
	return first, last, nil
}

func mutateLocalPolicy(db *sqlite.DB, fn func(context.Context) error) error {
	ctx := context.Background()
	for attempt := 0; attempt < 3; attempt++ {
		state, err := db.ConfigRevision(ctx, "policy")
		if err != nil {
			return err
		}
		_, err = db.MutateConfig(ctx, "policy", state.DesiredRevision, "", "", fn)
		if !errors.Is(err, sqlite.ErrRevisionConflict) {
			return err
		}
	}
	return sqlite.ErrRevisionConflict
}

// Package server runs WeroxyServer. The legacy entry stays closed unless a listen address is set.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"weroxy/server/internal/buildinfo"
	"weroxy/server/internal/catalog"
	"weroxy/server/internal/deployment"
	"weroxy/server/internal/firewallsync"
	"weroxy/server/internal/legacy"
	"weroxy/server/internal/logging"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	"weroxy/server/internal/ports"
	"weroxy/server/internal/quicklist"
	"weroxy/server/internal/secure"
	"weroxy/server/internal/storage/sqlite"
	"weroxy/server/internal/webui"
	"weroxy/server/internal/weroxy"
)

// Config is one process. Empty listen addresses stay closed.
type Config struct {
	DataDir       string
	Log           *logging.Logger
	LegacyListen  string
	WeroxyControl string
	WeroxyData    string
	QuickList     string
	QuickAllow    []string
	Web           string
	DrainTimeout  time.Duration
}

// Serve opens the database and waits until ctx is cancelled.
// Weroxy control without a data address is accepted only after the data-port pool is enabled.
func Serve(ctx context.Context, dataDir string, log *logging.Logger, legacyListen, weroxyControl, weroxyData string) error {
	return Start(ctx, Config{
		DataDir: dataDir, Log: log, LegacyListen: legacyListen,
		WeroxyControl: weroxyControl, WeroxyData: weroxyData,
	})
}

// Start opens the database, the requested listeners, and the quick list.
func Start(ctx context.Context, cfg Config) error {
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = 20 * time.Second
	}
	if cfg.DrainTimeout < time.Second || cfg.DrainTimeout > 5*time.Minute {
		return errors.New("drain timeout must be between 1s and 5m")
	}
	if err := Writable(cfg.DataDir); err != nil {
		return err
	}
	if cfg.Log == nil {
		cfg.Log = logging.New(logging.Options{Dir: filepath.Join(cfg.DataDir, "logs"), Err: os.Stderr})
		defer cfg.Log.Close()
	}
	if cfg.WeroxyControl == "" && cfg.WeroxyData != "" {
		return errors.New("weroxy control and data listeners must be set together")
	}
	db, err := sqlite.Open(filepath.Join(cfg.DataDir, "weroxy.db"), sqlite.DefaultQueue)
	if err != nil {
		return err
	}
	defer db.Close()
	webCtx, stopWeb := context.WithCancel(ctx)
	defer stopWeb()
	if cfg.Log != nil {
		budget, err := db.LogSettings(ctx)
		if err != nil {
			return err
		}
		if err := cfg.Log.SetBudget(budget.MaxFileMiB, budget.MaxTotalMiB, budget.MaxFiles, budget.RetainDays); err != nil {
			return err
		}
		if err := db.MarkConfigApplied(ctx, "logging", budget.Revision); err != nil {
			return err
		}
	}
	if err := preflightListeners(ctx, db, cfg); err != nil {
		return err
	}
	if cfg.WeroxyControl != "" && cfg.WeroxyData == "" {
		settings, err := db.PortPool(ctx)
		if err != nil {
			return err
		}
		if !settings.Enabled {
			return errors.New("weroxy control and data listeners must be set together")
		}
	}
	has, err := db.HasAdmin(ctx)
	if err != nil {
		return err
	}
	if has {
		cfg.Log.Info("administrator is initialized", nil)
	} else {
		cfg.Log.Info("administrator is not initialized; open the one-time Web setup path printed to the console", nil)
	}
	runCtx, cancelRun := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRun()
	reconcileCtx, stopReconcile := context.WithCancel(runCtx)
	defer stopReconcile()
	var reconcileWG sync.WaitGroup
	startReconcile := func(fn func()) { reconcileWG.Add(1); go func() { defer reconcileWG.Done(); fn() }() }
	firewall := firewallsync.New(db)
	startReconcile(func() { firewall.Run(reconcileCtx) })
	count := metrics.New()
	metricStatus := metrics.NewPersistStatus()
	savedTotals, err := db.LoadCurrentMetricTotals(ctx)
	if err != nil {
		return fmt.Errorf("cannot load durable metric totals: %w", err)
	}
	count.RestoreTotals(savedTotals)
	if err := db.InterruptOpenConnections(ctx); err != nil {
		return fmt.Errorf("cannot close prior connection records: %w", err)
	}
	rules := &policy.Table{}
	admit := policy.NewAdmission(1024)
	var policyRevision int64
	if cfg.WeroxyControl != "" || cfg.LegacyListen != "" {
		policyRevision, err = applyPolicy(ctx, db, rules, admit)
		if err != nil {
			return fmt.Errorf("cannot load access policy: %w", err)
		}
	}
	var weroxyRows func() []catalog.Row
	var legacyRows func() []catalog.Row
	var legacySvc *legacy.Service
	var weroxySvc *weroxy.Service
	var dataPorts func() int
	if cfg.WeroxyControl != "" {
		var ports func() int
		weroxySvc, ports, err = listenWeroxy(runCtx, cfg.DataDir, cfg.Log, db, cfg.WeroxyControl, cfg.WeroxyData, count, rules, admit)
		if err != nil {
			return err
		}
		weroxyRows = weroxySvc.Rows
		dataPorts = ports
	}
	if cfg.LegacyListen != "" {
		legacySvc, err = listenLegacy(runCtx, cfg.DataDir, cfg.Log, db, cfg.LegacyListen, count, rules, admit)
		if err != nil {
			return err
		}
		legacyRows = legacySvc.Rows
	}
	if weroxySvc != nil || legacySvc != nil {
		startReconcile(func() { pollDevices(reconcileCtx, db, legacySvc, weroxySvc) })
		startReconcile(func() { pollListenerConfig(reconcileCtx, db, legacySvc, weroxySvc, cfg.WeroxyData == "", cfg.DataDir) })
	}
	if cfg.WeroxyControl != "" || cfg.LegacyListen != "" {
		if err := db.MarkConfigApplied(ctx, "policy", policyRevision); err != nil {
			return err
		}
		startReconcile(func() { pollPolicy(reconcileCtx, db, rules, admit) })
	}
	if cfg.QuickList != "" {
		return errors.New("Quick List is served at --web /list; a separate --quick-list listener is unsupported")
	}
	if cfg.Web != "" {
		list := quicklist.NewHandler(quicklist.Options{
			Enabled: func() bool {
				queryCtx, cancel := context.WithTimeout(runCtx, time.Second)
				defer cancel()
				enabled, err := db.QuickListEnabled(queryCtx)
				return err == nil && enabled
			},
			Rows: func() []catalog.Row {
				var rows []catalog.Row
				if weroxyRows != nil {
					rows = append(rows, weroxyRows()...)
				}
				if legacyRows != nil {
					rows = append(rows, legacyRows()...)
				}
				return rows
			},
		})
		hub := &webui.Hub{}
		hub.SetSources(count, weroxyRows, legacyRows, dataPorts)
		var weroxyOnline, legacyOnline func() map[string]bool
		if weroxySvc != nil {
			weroxyOnline = weroxySvc.OnlineDevices
		}
		if legacySvc != nil {
			legacyOnline = legacySvc.OnlineDevices
		}
		hub.SetOnlineSources(weroxyOnline, legacyOnline)
		if weroxySvc != nil {
			hub.SetControlRTTs(weroxySvc.ControlRTTs)
		}
		if legacySvc != nil {
		}
		hub.SetPersistence(metricStatus)
		if _, err := webui.Start(webCtx, webui.Options{
			Addr: cfg.Web, QuickList: list, DB: db, Log: cfg.Log, Hub: hub, DataDir: cfg.DataDir,
			Firewall:  firewall,
			DataPlane: cfg.WeroxyControl != "" || cfg.LegacyListen != "",
			Ready: func() bool {
				return ctx.Err() == nil && (weroxySvc == nil || weroxySvc.Ready()) && (legacySvc == nil || legacySvc.Ready())
			},
		}); err != nil {
			return err
		}
		cfg.Log.Info("management web listening", map[string]string{"addr": cfg.Web})
	}
	persistCtx, stopPersistence := context.WithCancel(context.Background())
	defer stopPersistence()
	metricDone := make(chan struct{})
	connectionsDone := make(chan struct{})
	storageDone := make(chan struct{})
	go func() { defer close(metricDone); pollMetrics(persistCtx, db, count, metricStatus) }()
	go func() { defer close(connectionsDone); pollConnectionDetails(persistCtx, db, count) }()
	go func() { defer close(storageDone); pollStorage(persistCtx, db) }()
	cfg.Log.Info("server runtime started", nil)
	var shutdownError error
	select {
	case <-ctx.Done():
	case <-db.RecoveryFailure():
		shutdownError = sqlite.ErrRecoveryRequired
		stopWeb()
		cancelRun()
		cfg.DrainTimeout = time.Second
	}
	stopReconcile()
	reconcileWG.Wait()
	cfg.Log.Info("shutdown drain started", map[string]string{"timeout": cfg.DrainTimeout.String()})
	var drainWG sync.WaitGroup
	if weroxySvc != nil {
		drainWG.Add(1)
		go func() { defer drainWG.Done(); weroxySvc.Drain(cfg.DrainTimeout) }()
	}
	if legacySvc != nil {
		drainWG.Add(1)
		go func() { defer drainWG.Done(); legacySvc.Drain(cfg.DrainTimeout) }()
	}
	drainWG.Wait()
	cancelRun()
	cfg.Log.Info("shutdown drain finished", nil)
	stopPersistence()
	<-metricDone
	<-connectionsDone
	<-storageDone
	return shutdownError
}

func listenWeroxy(ctx context.Context, dataDir string, log *logging.Logger, db *sqlite.DB, controlAddr, dataAddr string, count *metrics.Counters, rules *policy.Table, admit *policy.Admission) (*weroxy.Service, func() int, error) {
	devices, forwards, err := db.ListWeroxy(ctx)
	if err != nil {
		return nil, nil, err
	}
	cached := make([]weroxy.Device, len(devices))
	for i, device := range devices {
		cached[i] = weroxy.Device{
			ID: device.ID, Name: device.Name, UID: device.UID, TokenMAC: device.TokenMAC, Credential: controlCredential(device.ClientKey), Revoked: device.Revoked, Paused: device.Paused,
		}
	}
	mapped := make([]weroxy.Forward, len(forwards))
	for i, forward := range forwards {
		mapped[i] = weroxy.Forward{
			ID: forward.ID, DeviceID: forward.DeviceID, Device: forward.Device, Listen: forward.Listen, Target: forward.Target,
			Mode: forward.Mode, Min: forward.Min, Preferred: forward.Preferred, Max: forward.Max,
			DeviceMax: forward.DeviceMax, Enabled: forward.Enabled, UseReserved: forward.UseReserved, ManualPorts: forward.ManualPorts,
		}
	}
	settings, err := db.PortPool(ctx)
	if err != nil {
		return nil, nil, err
	}
	opt := weroxy.Options{
		Devices:  cached,
		Forwards: mapped,
		Log:      log,
		Software: buildinfo.Version,
		Admit:    admit,
		Rules:    rules,
		Count:    count,
		Revoked: func() ([]string, error) {
			return db.RevokedWeroxyUIDs(ctx)
		},
	}
	if dataAddr == "" {
		opt.Pool = &ports.Pool{First: settings.DataFirst, Last: settings.DataLast, Reserved: settings.Reserved}
		filteredPool, err := deployment.FilterDataPool(dataDir, *opt.Pool)
		if err != nil {
			return nil, nil, err
		}
		opt.Pool = &filteredPool
		opt.PoolHost = settings.BindHost
		svc := weroxy.New(opt)
		boundControl, _, _, err := svc.StartAllocated(ctx, controlAddr)
		if err != nil {
			return nil, nil, err
		}
		if err := db.RegisterListener(ctx, "weroxy-control", boundControl); err != nil {
			return nil, nil, err
		}
		svc.StartHealth(ctx)
		return svc, svc.DataPorts, nil
	}
	svc := weroxy.New(opt)
	boundControl, boundData, _, err := svc.Start(ctx, controlAddr, dataAddr)
	if err != nil {
		return nil, nil, err
	}
	if err := db.RegisterListener(ctx, "weroxy-control", boundControl); err != nil {
		return nil, nil, err
	}
	if err := db.RegisterListener(ctx, "weroxy-data", boundData); err != nil {
		return nil, nil, err
	}
	return svc, func() int { return 1 }, nil
}

// pollDevices applies a coherent credential snapshot to each running adapter.
func pollDevices(ctx context.Context, db *sqlite.DB, legacySvc *legacy.Service, weroxySvc *weroxy.Service) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastPrepared := int64(-1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			state, err := db.ConfigRevision(queryCtx, "credential")
			if err != nil || state.DesiredRevision == lastPrepared {
				cancel()
				continue
			}
			var revision int64
			var oldDevices []legacy.Device
			var newDevices []weroxy.Device
			err = db.ReadSnapshot(queryCtx, func(readCtx context.Context) error {
				state, err := db.ConfigRevision(readCtx, "credential")
				if err != nil {
					return err
				}
				revision = state.DesiredRevision
				storedOld, _, err := db.ListLegacy(readCtx)
				if err != nil {
					return err
				}
				storedNew, _, err := db.ListWeroxy(readCtx)
				if err != nil {
					return err
				}
				oldDevices = make([]legacy.Device, len(storedOld))
				for i, item := range storedOld {
					oldDevices[i] = legacy.Device{ID: item.ID, Name: item.Name, KeyMAC: item.KeyMAC, Paused: item.Paused}
				}
				newDevices = make([]weroxy.Device, len(storedNew))
				for i, item := range storedNew {
					newDevices[i] = weroxy.Device{ID: item.ID, Name: item.Name, UID: item.UID, TokenMAC: item.TokenMAC, Credential: controlCredential(item.ClientKey), Revoked: item.Revoked, Paused: item.Paused}
				}
				return nil
			})
			cancel()
			if err != nil || revision == lastPrepared {
				continue
			}
			if weroxySvc != nil {
				if err := weroxySvc.ReconcileDevices(ctx, newDevices); err != nil {
					_ = db.MarkConfigFailed(ctx, "credential", revision, "credential_snapshot_invalid")
					continue
				}
			}
			if legacySvc != nil {
				if err := legacySvc.ReconcileDevices(ctx, oldDevices); err != nil {
					_ = db.MarkConfigFailed(ctx, "credential", revision, "credential_snapshot_invalid")
					continue
				}
			}
			if (legacySvc == nil && len(oldDevices) > 0) || (weroxySvc == nil && len(newDevices) > 0) {
				if err := db.MarkConfigFailed(ctx, "credential", revision, "protocol_not_running"); err != nil {
					continue
				}
			} else {
				if err := db.MarkConfigApplied(ctx, "credential", revision); err != nil {
					continue
				}
			}
			lastPrepared = revision
		}
	}
}

// pollListenerConfig applies a coherent saved snapshot to both protocol adapters.
// The revision advances only after every configured adapter has accepted it.
func pollListenerConfig(ctx context.Context, db *sqlite.DB, legacySvc *legacy.Service, weroxySvc *weroxy.Service, pooled bool, dataDir string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastPrepared := int64(-1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			state, err := db.ConfigRevision(queryCtx, "listener")
			if err != nil || !pooled && state.DesiredRevision == lastPrepared && state.AppliedRevision == state.DesiredRevision {
				cancel()
				continue
			}
			var revision int64
			var old []legacy.Forward
			var next []weroxy.Forward
			var assignments []ports.Assignment
			var settings sqlite.PortSettings
			err = db.ReadSnapshot(queryCtx, func(readCtx context.Context) error {
				current, err := db.ConfigRevision(readCtx, "listener")
				if err != nil {
					return err
				}
				revision = current.DesiredRevision
				_, oldRows, err := db.ListLegacy(readCtx)
				if err != nil {
					return err
				}
				_, newRows, err := db.ListWeroxy(readCtx)
				if err != nil {
					return err
				}
				settings, err = db.PortPool(readCtx)
				if err != nil {
					return err
				}
				assignments, err = db.ListAssignments(readCtx)
				if err != nil {
					return err
				}
				old = make([]legacy.Forward, len(oldRows))
				for i, item := range oldRows {
					old[i] = legacy.Forward{ID: item.ID, DeviceID: item.DeviceID, Listen: item.Listen, Target: item.Target}
				}
				next = make([]weroxy.Forward, len(newRows))
				for i, item := range newRows {
					next[i] = weroxy.Forward{ID: item.ID, DeviceID: item.DeviceID, Device: item.Device, Listen: item.Listen, Target: item.Target,
						Mode: item.Mode, Min: item.Min, Preferred: item.Preferred, Max: item.Max,
						DeviceMax: item.DeviceMax, Enabled: item.Enabled, UseReserved: item.UseReserved, ManualPorts: item.ManualPorts}
				}
				return nil
			})
			cancel()
			if err != nil || !pooled && revision == lastPrepared && state.AppliedRevision == revision {
				continue
			}
			if legacySvc == nil && len(old) != 0 || weroxySvc == nil && len(next) != 0 {
				_ = db.MarkConfigFailed(ctx, "listener", revision, "protocol_not_running")
				lastPrepared = revision
				continue
			}
			if pooled && weroxySvc != nil && !settings.Enabled {
				_ = db.MarkConfigFailed(ctx, "listener", revision, "data_pool_disabled")
				lastPrepared = revision
				continue
			}
			commitNew, abortNew := func() {}, func() {}
			commitOld, abortOld := func() {}, func() {}
			if weroxySvc != nil {
				var pool *ports.Pool
				if pooled {
					pool = &ports.Pool{First: settings.DataFirst, Last: settings.DataLast, Reserved: settings.Reserved}
					filtered, filterErr := deployment.FilterDataPool(dataDir, *pool)
					if filterErr != nil {
						_ = db.MarkConfigFailed(ctx, "listener", revision, "publication_unverified")
						continue
					}
					pool = &filtered
					assignments = weroxySvc.AdaptiveAssignments(next, assignments, *pool)
				}
				commitNew, abortNew, err = weroxySvc.PrepareAvailableForwards(ctx, next, assignments, pool, settings.BindHost)
				if err != nil {
					_ = db.MarkConfigFailed(ctx, "listener", revision, "listener_prepare_failed")
					continue
				}
			}
			if legacySvc != nil {
				commitOld, abortOld, err = legacySvc.PrepareForwards(ctx, old)
				if err != nil {
					abortNew()
					_ = db.MarkConfigFailed(ctx, "listener", revision, "listener_prepare_failed")
					continue
				}
			}
			if ctx.Err() != nil {
				abortOld()
				abortNew()
				return
			}
			// No fallible bind remains after both adapters have prepared.
			commitNew()
			commitOld()
			if pooled && weroxySvc != nil {
				actual := weroxySvc.SnapshotForwards()
				if err := db.RecordRuntimeAssignments(ctx, revision, actual.Assignments); err != nil {
					_ = db.MarkConfigFailed(ctx, "listener", revision, "assignment_record_failed")
					continue
				}
			}

			if state.AppliedRevision == revision && state.FailureReason == "" {
				lastPrepared = revision
				continue
			}
			if err := db.MarkConfigApplied(ctx, "listener", revision); err == nil {
				lastPrepared = revision
			}
		}
	}
}

func pollPolicy(ctx context.Context, db *sqlite.DB, rules *policy.Table, admit *policy.Admission) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastSweep time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(lastSweep) >= time.Minute {
				if _, err := db.ExpireAccessRules(ctx, time.Now().UTC()); err == nil {
					lastSweep = time.Now()
				}
			}
			state, err := db.ConfigRevision(ctx, "policy")
			if err != nil || state.DesiredRevision == state.AppliedRevision && state.FailureReason == "" {
				continue
			}
			revision, err := applyPolicy(ctx, db, rules, admit)
			if err != nil {
				_ = db.MarkConfigFailed(ctx, "policy", state.DesiredRevision, "policy_snapshot_invalid")
				continue
			}
			_ = db.MarkConfigApplied(ctx, "policy", revision)
		}
	}
}

// applyPolicy reads policy rows, bans and their desired revision from one
// SQLite snapshot. Invalid or unavailable snapshots leave the active tables.
func applyPolicy(ctx context.Context, db *sqlite.DB, rules *policy.Table, admit *policy.Admission) (int64, error) {
	var revision int64
	var global policy.Rule
	var device map[string]policy.Rule
	var forward map[string]policy.Rule
	var bans []policy.Ban
	var allows []policy.Allow
	err := db.ReadSnapshot(ctx, func(readCtx context.Context) error {
		state, err := db.ConfigRevision(readCtx, "policy")
		if err != nil {
			return err
		}
		revision = state.DesiredRevision
		stored, err := db.ListPolicies(readCtx)
		if err != nil {
			return err
		}
		device = map[string]policy.Rule{}
		forward = map[string]policy.Rule{}
		for key, values := range stored {
			scope, name, _ := strings.Cut(key, "\n")
			switch scope {
			case "global":
				global = values.Rule()
			case "device":
				device[name] = values.Rule()
			case "forward":
				forward[name] = values.Rule()
			}
		}
		access, err := db.ListAccessRules(readCtx)
		if err != nil {
			return err
		}
		for _, rule := range access {
			_, network, parseErr := net.ParseCIDR(rule.CIDR)
			if parseErr != nil {
				return fmt.Errorf("invalid stored access CIDR")
			}
			if rule.Action == "ban" {
				bans = append(bans, policy.Ban{Scope: rule.Scope, Key: rule.Key, Net: network})
			} else if rule.Action == "allow" {
				allows = append(allows, policy.Allow{Scope: rule.Scope, Key: rule.Key, Net: network})
			} else {
				return fmt.Errorf("invalid stored access action")
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	admit.SetLimits(bans, allows)
	rules.Replace(global, device, forward)
	return revision, nil
}

func listenLegacy(ctx context.Context, dataDir string, log *logging.Logger, db *sqlite.DB, addr string, count *metrics.Counters, rules *policy.Table, admit *policy.Admission) (*legacy.Service, error) {
	devices, forwards, err := db.ListLegacy(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := legacy.LoadSecret(dataDir, false)
	if len(devices) > 0 && errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("缺少 %s，无法校验已保存的 Client Key", legacy.SecretFile)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	cached := make([]legacy.Device, len(devices))
	for i, device := range devices {
		cached[i] = legacy.Device{ID: device.ID, Name: device.Name, KeyMAC: device.KeyMAC, Paused: device.Paused}
	}
	mapped := make([]legacy.Forward, len(forwards))
	for i, forward := range forwards {
		mapped[i] = legacy.Forward{ID: forward.ID, DeviceID: forward.DeviceID, Listen: forward.Listen, Target: forward.Target}
	}
	svc := legacy.New(legacy.Options{
		Secret:   secret,
		Devices:  cached,
		Forwards: mapped,
		Log:      log,
		Count:    count,
		Admit:    admit,
		Rules:    rules,
	})
	// The lookup cache is the slice above. Business bytes do not read SQLite.
	if _, _, err := svc.Start(ctx, addr); err != nil {
		return nil, err
	}
	for role, address := range svc.EntryAddresses() {
		if err := db.RegisterListener(ctx, role, address); err != nil {
			return nil, err
		}
	}
	return svc, nil
}

// Writable reports whether the data directory can be created and written by this user.
func Writable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("数据目录不可写。请将属主设为 10001:10001，不要使用 0777: %w", err)
	}
	file, err := os.CreateTemp(dir, ".weroxy-write-*")
	if err != nil {
		return fmt.Errorf("数据目录不可写。请将属主设为 10001:10001，不要使用 0777: %w", err)
	}
	name := file.Name()
	closeErr := file.Close()
	removeErr := os.Remove(name)
	if err := errors.Join(closeErr, removeErr); err != nil {
		return err
	}
	return nil
}

// pollMetrics writes absolute snapshots on a low-priority bounded queue. A
// failed tick is covered by the next absolute snapshot; no forwarding path
// waits for SQLite. Shutdown flushes once before the database is closed.
func pollMetrics(ctx context.Context, db *sqlite.DB, count *metrics.Counters, status *metrics.PersistStatus) {
	interval := 5 * time.Second
	persist := func(parent context.Context) {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			status.Record(time.Now().UTC(), "random_failed")
			return
		}
		queryCtx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		sampledAt := time.Now().UTC()
		saved := count.TotalsSnapshot()
		err := db.WriteMetricSnapshot(queryCtx, hex.EncodeToString(raw[:]), sampledAt, saved, interval)
		if err == nil {
			if current, readErr := db.LoadCurrentMetricTotals(queryCtx); readErr == nil {
				count.PruneTotals(current, saved)
			}
		}
		reason := ""
		if err != nil {
			reason = "write_failed"
			if errors.Is(err, sqlite.ErrTelemetryDisk) {
				reason = "disk_protection"
			}
			if errors.Is(err, sqlite.ErrQueueFull) {
				reason = "queue_full"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				reason = "write_timeout"
			}
		}
		status.Record(sampledAt, reason)
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	configuration := time.NewTicker(5 * time.Second)
	defer configuration.Stop()
	applied := int64(-1)
	reload := func() {
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		item, err := db.MetricSettings(queryCtx)
		if err != nil {
			return
		}
		next := time.Duration(item.SampleSec) * time.Second
		if next != interval {
			interval = next
			ticker.Reset(interval)
		}
		retention, err := db.HistoryRetention(queryCtx)
		if err != nil || !retention.Valid() {
			_ = db.MarkConfigFailed(queryCtx, "storage", item.Revision, "retention_invalid")
			return
		}
		if item.Revision != applied {
			if db.MarkConfigApplied(queryCtx, "storage", item.Revision) == nil {
				applied = item.Revision
			}
		}
	}
	reload()
	pruneHistory := func(now time.Time) {
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_ = db.PruneMetricHistory(queryCtx, now)
		cancel()
		queryCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		_ = db.PruneConnections(queryCtx, now)
		cancel()
		queryCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		_ = db.PruneAudits(queryCtx, now)
		cancel()
	}
	pruneHistory(time.Now())
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			persist(flushCtx)
			cancel()
			return
		case <-ticker.C:
			persist(ctx)
		case <-configuration.C:
			reload()
		case now := <-prune.C:
			pruneHistory(now)
		}
	}
}

// pollConnectionDetails drains at most 256 changed sessions per tick. The
// forwarding goroutines only update bounded memory; SQLite uses its low queue.
func pollConnectionDetails(ctx context.Context, db *sqlite.DB, count *metrics.Counters) {
	write := func(parent context.Context) bool {
		totals := count.DrainVisitorTotals(256)
		if len(totals) > 0 {
			q, cancel := context.WithTimeout(parent, 2*time.Second)
			err := db.SaveVisitorTotals(q, totals)
			cancel()
			if err != nil {
				count.RequeueVisitorTotals(totals)
				return false
			}
		}
		items := count.DrainDetails(256)
		if len(items) == 0 {
			return len(totals) > 0
		}
		queryCtx, cancel := context.WithTimeout(parent, 2*time.Second)
		err := db.SaveConnections(queryCtx, items)
		cancel()
		if err != nil {
			count.RequeueDetails(items)
			return false
		}
		return true
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			for flushCtx.Err() == nil && write(flushCtx) {
			}
			return
		case <-ticker.C:
			write(ctx)
		}
	}
}

func pollStorage(ctx context.Context, db *sqlite.DB) {
	refresh := func() { db.RefreshDisk() }
	refresh()
	diskTicker := time.NewTicker(15 * time.Second)
	defer diskTicker.Stop()
	checkpoint := func() {
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_ = db.CheckpointPassive(queryCtx)
	}
	checkpoint()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-diskTicker.C:
			refresh()
		case <-ticker.C:
			if !db.TelemetryAllowed() {
				cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_ = db.PruneMetricHistory(cleanupCtx, time.Now())
				cancel()
				cleanupCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
				_ = db.PruneConnections(cleanupCtx, time.Now())
				cancel()
			}
			checkpoint()
		}
	}
}

func controlCredential(key string) secure.Credential {
	raw, err := hex.DecodeString(key)
	if err != nil {
		return secure.Credential{}
	}
	defer clear(raw)
	return secure.Derive(raw, "control")
}

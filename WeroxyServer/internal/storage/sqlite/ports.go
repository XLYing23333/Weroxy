package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"weroxy/server/internal/policy"
	"weroxy/server/internal/ports"
)

var (
	// ErrPortConflict means the listen address overlaps a claimed port.
	ErrPortConflict = errors.New("port conflict")
	// ErrPortRange means a pool or min/preferred/max is invalid.
	ErrPortRange = errors.New("port range")
	// ErrPolicyLooser means a child policy would exceed its parent.
	ErrPolicyLooser = errors.New("policy looser than parent")
)

// PortSettings is the configured forward and data ranges.
type PortSettings struct {
	Enabled      bool
	ForwardFirst int
	ForwardLast  int
	DataFirst    int
	DataLast     int
	Reserved     int
	BindHost     string
}

// PolicyValues is one stored limit row. Nil pointers inherit.
type PolicyValues struct {
	MaxPending *int
	MaxPerIP   *int
	RatePerSec *int
	Burst      *int
	IdleSec    *int
	ConnectSec *int
	WaitSec    *int
	Bandwidth  *int
}

// AccessRule is a ban or an allow.
type AccessRule struct {
	Scope        string
	Key          string
	Action       string
	CIDR         string
	ExpiresAt    *time.Time
	KernelStatus string
	RetryCount   int
	Generation   int64
}

// SetPortPool stores an enabled range. Ordinary allocation will not use the reserved tail.
func (db *DB) SetPortPool(ctx context.Context, settings PortSettings) error {
	if settings.ForwardFirst < 1 || settings.ForwardLast < settings.ForwardFirst || settings.ForwardLast > 65535 {
		return ErrPortRange
	}
	if settings.DataFirst < 1 || settings.DataLast < settings.DataFirst || settings.DataLast > 65535 || settings.Reserved < 0 {
		return ErrPortRange
	}
	if settings.Reserved > settings.DataLast-settings.DataFirst+1 {
		return ErrPortRange
	}
	if overlaps(settings.ForwardFirst, settings.ForwardLast, settings.DataFirst, settings.DataLast) {
		return ErrPortRange
	}
	if settings.BindHost == "" {
		settings.BindHost = "0.0.0.0"
	}
	if net.ParseIP(settings.BindHost) == nil {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		claims, err := claimsTx(ctx, tx)
		if err != nil {
			return err
		}
		for _, claim := range claims {
			inData := claim.Port >= settings.DataFirst && claim.Port <= settings.DataLast
			inForward := claim.Port >= settings.ForwardFirst && claim.Port <= settings.ForwardLast
			if claim.Role == "data" {
				continue
			}
			if (inData || inForward && claim.Role != "forward") && ports.Conflicts(claim, ports.Endpoint{Host: settings.BindHost, Port: claim.Port}) {
				return ErrPortConflict
			}
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE port_settings
			SET enabled = 1, forward_first = ?, forward_last = ?, data_first = ?, data_last = ?, reserved = ?, bind_host = ?
			WHERE id = 1`,
			settings.ForwardFirst, settings.ForwardLast, settings.DataFirst, settings.DataLast, settings.Reserved, settings.BindHost,
		)
		if err != nil {
			return err
		}
		return insertAudit(ctx, tx, "port_pool_set", "success", "", time.Now().UTC().Format(time.RFC3339Nano))
	})
}

// PortPool reads the saved range.
func (db *DB) PortPool(ctx context.Context) (PortSettings, error) {
	var item PortSettings
	var enabled int
	err := db.QueryRow(ctx, `SELECT enabled, forward_first, forward_last, data_first, data_last, reserved, bind_host FROM port_settings WHERE id = 1`).
		Scan(&enabled, &item.ForwardFirst, &item.ForwardLast, &item.DataFirst, &item.DataLast, &item.Reserved, &item.BindHost)
	item.Enabled = enabled != 0
	return item, err
}

func replaceAssignments(ctx context.Context, tx *sql.Tx, items []ports.Assignment) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM data_assignments`); err != nil {
		return err
	}
	for _, item := range items {
		state := item.State
		if state == "" {
			state = ports.Serving
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO data_assignments(forward_id, port, state) VALUES (?, ?, ?)`, item.ForwardID, item.Port, state); err != nil {
			return err
		}
	}
	return nil
}

// ListAssignments reads the saved data-port bindings.
func (db *DB) ListAssignments(ctx context.Context) ([]ports.Assignment, error) {
	rows, err := db.QueryRows(ctx, `
		SELECT a.forward_id, f.device_id, a.port, a.state
		FROM data_assignments a JOIN weroxy_forwards f ON f.id = a.forward_id
		ORDER BY a.port, a.forward_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ports.Assignment
	for rows.Next() {
		var item ports.Assignment
		if err := rows.Scan(&item.ForwardID, &item.DeviceID, &item.Port, &item.State); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SetPolicy upserts one scope. A child that is looser than its parent is rejected.
func (db *DB) SetPolicy(ctx context.Context, scope, key string, values PolicyValues) error {
	if !values.Valid() {
		return ErrPolicyInvalid
	}
	if scope != "global" && scope != "device" && scope != "forward" {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		parent, err := parentRule(ctx, tx, scope, key)
		if err != nil {
			return err
		}
		child := values.Rule()
		if policy.Looser(parent, child) {
			return ErrPolicyLooser
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM access_policies WHERE scope = ? AND scope_key = ?`, scope, key)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO access_policies(scope, scope_key, max_pending, max_per_ip, rate_per_sec, burst, idle_sec, connect_sec, wait_sec, bandwidth)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scope, key, intPtr(values.MaxPending), intPtr(values.MaxPerIP), intPtr(values.RatePerSec), intPtr(values.Burst),
			intPtr(values.IdleSec), intPtr(values.ConnectSec), intPtr(values.WaitSec), intPtr(values.Bandwidth),
		)
		return err
	})
}

// ListPolicies reads every stored rule.
func (db *DB) ListPolicies(ctx context.Context) (map[string]PolicyValues, error) {
	rows, err := db.QueryRows(ctx, `SELECT scope, scope_key, max_pending, max_per_ip, rate_per_sec, burst, idle_sec, connect_sec, wait_sec, bandwidth FROM access_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]PolicyValues{}
	for rows.Next() {
		var scope, key string
		var pending, perIP, rate, burst, idle, connect, wait, bandwidth sql.NullInt64
		if err := rows.Scan(&scope, &key, &pending, &perIP, &rate, &burst, &idle, &connect, &wait, &bandwidth); err != nil {
			return nil, err
		}
		values := PolicyValues{
			MaxPending: nullInt(pending), MaxPerIP: nullInt(perIP), RatePerSec: nullInt(rate), Burst: nullInt(burst),
			IdleSec: nullInt(idle), ConnectSec: nullInt(connect), WaitSec: nullInt(wait), Bandwidth: nullInt(bandwidth),
		}
		if !values.Valid() {
			return nil, ErrPolicyInvalid
		}
		out[scope+"\n"+key] = values
	}
	return out, rows.Err()
}

// AddAccessRule stores a ban or an allow. The CIDR must parse.
func (db *DB) AddAccessRule(ctx context.Context, rule AccessRule) error {
	cidr, err := canonicalAccessCIDR(rule.CIDR)
	if err != nil {
		return err
	}
	rule.CIDR = cidr
	if rule.Scope != "global" && rule.Scope != "device" && rule.Scope != "forward" {
		return ErrPortRange
	}
	if rule.Scope == "global" && rule.Key != "" {
		return ErrPortRange
	}
	if rule.Action != "ban" && rule.Action != "allow" {
		return ErrPortRange
	}
	if rule.ExpiresAt != nil && (!rule.ExpiresAt.After(time.Now()) || rule.ExpiresAt.After(time.Now().Add(24*time.Hour))) {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		// Include older textual variants without rewriting executed migrations.
		rows, err := tx.QueryContext(ctx, `SELECT cidr FROM access_rules WHERE scope=? AND scope_key=? AND action=? AND (expires_at IS NULL OR expires_at>?) LIMIT 4097`, rule.Scope, rule.Key, rule.Action, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		for rows.Next() {
			var existing string
			if err := rows.Scan(&existing); err != nil {
				rows.Close()
				return err
			}
			canonical, err := canonicalAccessCIDR(existing)
			if err == nil && canonical == rule.CIDR {
				rows.Close()
				return ErrAccessRuleExists
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_rules`).Scan(&count); err != nil {
			return err
		}
		if count >= 4096 {
			return ErrPortRange
		}
		var expiry any
		if rule.ExpiresAt != nil {
			expiry = rule.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO access_rules(scope, scope_key, action, cidr, created_at, expires_at, kernel_status) VALUES (?, ?, ?, ?, ?, ?, 'unsupported')`,
			rule.Scope, rule.Key, rule.Action, rule.CIDR, time.Now().UTC().Format(time.RFC3339Nano), expiry)
		return err
	})
}

// ListAccessRules reads bans and allows.
func (db *DB) ListAccessRules(ctx context.Context) ([]AccessRule, error) {
	rows, err := db.QueryRows(ctx, `SELECT scope, scope_key, action, cidr, expires_at, kernel_status, kernel_retry_count, policy_generation
		FROM access_rules WHERE expires_at IS NULL OR expires_at > ? ORDER BY id`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []AccessRule
	for rows.Next() {
		var rule AccessRule
		var expiry sql.NullString
		if err := rows.Scan(&rule.Scope, &rule.Key, &rule.Action, &rule.CIDR, &expiry, &rule.KernelStatus, &rule.RetryCount, &rule.Generation); err != nil {
			return nil, err
		}
		if expiry.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, expiry.String)
			if err != nil {
				return nil, err
			}
			rule.ExpiresAt = &parsed
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ExpireAccessRules removes elapsed rules and advances the policy desired
// revision in the same transaction, so the runtime coordinator reloads them.
func (db *DB) ExpireAccessRules(ctx context.Context, now time.Time) (int64, error) {
	var removed int64
	err := db.Do(ctx, func(tx *sql.Tx) error {
		stamp := now.UTC().Format(time.RFC3339Nano)
		result, err := tx.ExecContext(ctx, `DELETE FROM access_rules WHERE expires_at IS NOT NULL AND expires_at <= ?`, stamp)
		if err != nil {
			return err
		}
		removed, err = result.RowsAffected()
		if err != nil || removed == 0 {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE config_revisions SET desired_revision = desired_revision + 1, failure_reason = '', updated_at = ? WHERE domain = 'policy'`, stamp); err != nil {
			return err
		}
		return insertAudit(ctx, tx, "access_rule_expire", "success", "count="+strconv.FormatInt(removed, 10), stamp)
	})
	return removed, err
}

// DeleteAccessRule removes one stored ban or allow. The CIDR must match the saved text.
func (db *DB) DeleteAccessRule(ctx context.Context, rule AccessRule) error {
	canonical, err := canonicalAccessCIDR(rule.CIDR)
	if err != nil {
		return err
	}
	if rule.Action != "ban" && rule.Action != "allow" {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,cidr FROM access_rules WHERE scope=? AND scope_key=? AND action=? LIMIT 4097`, rule.Scope, rule.Key, rule.Action)
		if err != nil {
			return err
		}
		ids := []any{}
		placeholders := []string{}
		scanned := 0
		for rows.Next() {
			var id int64
			var cidr string
			if err := rows.Scan(&id, &cidr); err != nil {
				rows.Close()
				return err
			}
			scanned++
			if scanned > 4096 {
				rows.Close()
				return ErrPortRange
			}
			existing, err := canonicalAccessCIDR(cidr)
			if cidr == rule.CIDR || (err == nil && existing == canonical) {
				ids = append(ids, id)
				placeholders = append(placeholders, "?")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return ErrWeroxyNotFound
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM access_rules WHERE id IN (`+strings.Join(placeholders, ",")+`)`, ids...)
		return err
	})
}

// ListenClaims returns addresses that a new listener must not overlap.
func (db *DB) ListenClaims(ctx context.Context) ([]ports.Endpoint, error) {
	claims, err := listenerClaims(ctx, db.sql)
	if err != nil {
		return nil, err
	}
	appendListen := func(query string) error {
		rows, err := db.sql.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var listen string
			if err := rows.Scan(&listen); err != nil {
				return err
			}
			host, port, ok := ports.ParseHostPort(listen)
			if !ok {
				continue
			}
			claims = append(claims, ports.Endpoint{Host: host, Port: port, Role: "forward"})
		}
		return rows.Err()
	}
	if err := appendListen(`SELECT listen FROM legacy_forwards`); err != nil {
		return nil, err
	}
	if err := appendListen(`SELECT listen FROM weroxy_forwards`); err != nil {
		return nil, err
	}
	settings, err := db.PortPool(ctx)
	if err != nil {
		return nil, err
	}
	if settings.Enabled {
		for port := settings.DataFirst; port <= settings.DataLast; port++ {
			claims = append(claims, ports.Endpoint{Host: settings.BindHost, Port: port, Role: "data"})
		}
	}
	return claims, nil
}

// Rule converts stored pointers into a policy rule.
func (v PolicyValues) Rule() policy.Rule {
	return policy.Rule{
		MaxPending: limitOf(v.MaxPending),
		MaxPerIP:   limitOf(v.MaxPerIP),
		RatePerSec: limitOf(v.RatePerSec),
		Burst:      limitOf(v.Burst),
		IdleSec:    limitOf(v.IdleSec),
		ConnectSec: limitOf(v.ConnectSec),
		WaitSec:    limitOf(v.WaitSec),
		Bandwidth:  limitOf(v.Bandwidth),
	}
}

func limitOf(value *int) policy.Limit {
	if value == nil {
		return policy.Limit{}
	}
	return policy.Limit{Set: true, Value: *value}
}

func intPtr(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullInt(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	n := int(value.Int64)
	return &n
}

func parentRule(ctx context.Context, tx *sql.Tx, scope, key string) (policy.Rule, error) {
	global, err := loadRule(ctx, tx, "global", "")
	if err != nil {
		return policy.Rule{}, err
	}
	if scope == "global" {
		return policy.Rule{}, nil
	}
	if scope == "device" {
		return global, nil
	}
	deviceName, _, _ := splitForwardKey(key)
	device, err := loadRule(ctx, tx, "device", deviceName)
	if err != nil {
		return policy.Rule{}, err
	}
	return policy.Effective(global, device, policy.Rule{}), nil
}

func loadRule(ctx context.Context, tx *sql.Tx, scope, key string) (policy.Rule, error) {
	var pending, perIP, rate, burst, idle, connect, wait, bandwidth sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT max_pending, max_per_ip, rate_per_sec, burst, idle_sec, connect_sec, wait_sec, bandwidth FROM access_policies WHERE scope = ? AND scope_key = ?`, scope, key).
		Scan(&pending, &perIP, &rate, &burst, &idle, &connect, &wait, &bandwidth)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.Rule{}, nil
	}
	if err != nil {
		return policy.Rule{}, err
	}
	return (PolicyValues{
		MaxPending: nullInt(pending), MaxPerIP: nullInt(perIP), RatePerSec: nullInt(rate), Burst: nullInt(burst),
		IdleSec: nullInt(idle), ConnectSec: nullInt(connect), WaitSec: nullInt(wait), Bandwidth: nullInt(bandwidth),
	}).Rule(), nil
}

func splitForwardKey(key string) (string, string, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:], true
		}
	}
	return key, "", false
}

func conflictListen(ctx context.Context, tx *sql.Tx, listen string) error {
	host, port, ok := ports.ParseHostPort(listen)
	if !ok {
		return ErrPortRange
	}
	claims, err := claimsTx(ctx, tx)
	if err != nil {
		return err
	}
	if _, hit := ports.FirstConflict(claims, ports.Endpoint{Host: host, Port: port, Role: "forward"}); hit {
		return ErrPortConflict
	}
	return nil
}

func claimsTx(ctx context.Context, tx *sql.Tx) ([]ports.Endpoint, error) {
	claims, err := listenerClaims(ctx, tx)
	if err != nil {
		return nil, err
	}
	collect := func(query string) error {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var listen string
			if err := rows.Scan(&listen); err != nil {
				return err
			}
			host, port, ok := ports.ParseHostPort(listen)
			if !ok {
				continue
			}
			claims = append(claims, ports.Endpoint{Host: host, Port: port, Role: "forward"})
		}
		return rows.Err()
	}
	if err := collect(`SELECT listen FROM legacy_forwards`); err != nil {
		return nil, err
	}
	if err := collect(`SELECT listen FROM weroxy_forwards`); err != nil {
		return nil, err
	}
	var enabled int
	var first, last int
	var host string
	err = tx.QueryRowContext(ctx, `SELECT enabled, data_first, data_last, bind_host FROM port_settings WHERE id = 1`).Scan(&enabled, &first, &last, &host)
	if err != nil {
		return nil, err
	}
	if enabled != 0 {
		for port := first; port <= last; port++ {
			claims = append(claims, ports.Endpoint{Host: host, Port: port, Role: "data"})
		}
	}
	return claims, nil
}

func allocateTx(ctx context.Context, tx *sql.Tx, newID int64) error {
	var enabled int
	var first, last, reserved int
	err := tx.QueryRowContext(ctx, `SELECT enabled, data_first, data_last, reserved FROM port_settings WHERE id = 1`).Scan(&enabled, &first, &last, &reserved)
	if err != nil || enabled == 0 {
		return err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id, f.device_id, f.sharing_mode, f.min_ports, f.preferred_ports, f.max_ports, f.enabled, f.use_reserved, d.max_data_ports, f.manual_data_ports
		FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id
		ORDER BY f.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var specs []ports.Spec
	for rows.Next() {
		var spec ports.Spec
		var manual string
		var on, reserved int
		var deviceMax sql.NullInt64
		if err := rows.Scan(&spec.ID, &spec.DeviceID, &spec.Mode, &spec.Min, &spec.Preferred, &spec.Max, &on, &reserved, &deviceMax, &manual); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(manual), &spec.ManualPorts); err != nil {
			return err
		}
		spec.Enabled = on != 0
		spec.UseReserved = reserved != 0
		if deviceMax.Valid {
			spec.DeviceMax = int(deviceMax.Int64)
		}
		specs = append(specs, spec)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out := ports.Allocate(ports.Pool{First: first, Last: last, Reserved: reserved}, specs)
	if newID != 0 {
		if reason := out.Rejected[newID]; reason != "" {
			return ErrPortQuota
		}
	} else {
		for id, reason := range out.Rejected {
			if id != 0 && reason != "" {
				return ErrPortQuota
			}
		}
	}
	return replaceAssignments(ctx, tx, out.Assignments)
}

func forwardInPool(ctx context.Context, tx *sql.Tx, listen string, allowOutside bool) error {
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM port_settings WHERE id = 1`).Scan(&enabled); err != nil {
		return err
	}
	if enabled == 0 {
		return nil
	}
	allowed, err := forwardPortAllowed(ctx, tx, listen)
	if err != nil {
		return err
	}
	if !allowed && allowOutside {
		_, err := tx.ExecContext(ctx, `INSERT INTO forward_port_exceptions(listen, origin, created_at) VALUES (?, 'manual_import', ?) ON CONFLICT(listen) DO NOTHING`, listen, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	}
	if !allowed {
		return ErrPortRange
	}
	return nil
}

// ShrinkForward lowers one forward's maximum and drains the highest ports.
// Sessions already using a drained port are left recorded until the process drops them.
func (db *DB) ShrinkForward(ctx context.Context, device, listen string, maxPorts int) error {
	if maxPorts < 1 {
		return ErrPortRange
	}
	return db.Do(ctx, func(tx *sql.Tx) error {
		var id int64
		var minPorts, preferred int
		err := tx.QueryRowContext(ctx, `
			SELECT f.id, f.min_ports, f.preferred_ports
			FROM weroxy_forwards f JOIN weroxy_devices d ON d.id = f.device_id
			WHERE d.name = ? AND f.listen = ?`, device, listen).Scan(&id, &minPorts, &preferred)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWeroxyNotFound
		}
		if err != nil {
			return err
		}
		if minPorts > maxPorts {
			return ErrPortRange
		}
		if preferred > maxPorts {
			preferred = maxPorts
		}
		if _, err := tx.ExecContext(ctx, `UPDATE weroxy_forwards SET max_ports = ?, preferred_ports = ? WHERE id = ?`, maxPorts, preferred, id); err != nil {
			return err
		}
		items, err := listAssignmentsTx(ctx, tx)
		if err != nil {
			return err
		}
		return replaceAssignments(ctx, tx, ports.MarkDrain(items, id, maxPorts))
	})
}

func listAssignmentsTx(ctx context.Context, tx *sql.Tx) ([]ports.Assignment, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.forward_id, f.device_id, a.port, a.state
		FROM data_assignments a JOIN weroxy_forwards f ON f.id = a.forward_id
		ORDER BY a.port, a.forward_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ports.Assignment
	for rows.Next() {
		var item ports.Assignment
		if err := rows.Scan(&item.ForwardID, &item.DeviceID, &item.Port, &item.State); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SetDeviceDataMax stores the device data-port union cap. A negative max clears it.
// The change is rejected when the forwards already stored would no longer fit.
func (db *DB) SetDeviceDataMax(ctx context.Context, name string, maxPorts int) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var value any
		if maxPorts >= 0 {
			value = maxPorts
		}
		result, err := tx.ExecContext(ctx, `UPDATE weroxy_devices SET max_data_ports = ? WHERE name = ?`, value, name)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrWeroxyNotFound
		}
		return allocateTx(ctx, tx, 0)
	})
}

// Capacity is the allocator view of the saved forwards and assignments.
func (db *DB) Capacity(ctx context.Context) (ports.Pool, []ports.View, error) {
	settings, err := db.PortPool(ctx)
	if err != nil {
		return ports.Pool{}, nil, err
	}
	_, forwards, err := db.ListWeroxy(ctx)
	if err != nil {
		return ports.Pool{}, nil, err
	}
	pool := ports.Pool{First: settings.DataFirst, Last: settings.DataLast, Reserved: settings.Reserved}
	specs := make([]ports.Spec, 0, len(forwards))
	for _, forward := range forwards {
		specs = append(specs, ports.Spec{
			ID: forward.ID, DeviceID: forward.DeviceID, Mode: forward.Mode,
			Min: forward.Min, Preferred: forward.Preferred, Max: forward.Max,
			DeviceMax: forward.DeviceMax, Enabled: forward.Enabled, UseReserved: forward.UseReserved,
		})
	}
	items, err := db.ListAssignments(ctx)
	if err != nil {
		return ports.Pool{}, nil, err
	}
	views := ports.Preview(pool, specs, items)
	out := make([]ports.View, 0, len(views))
	for _, forward := range forwards {
		out = append(out, views[forward.ID])
	}
	return pool, out, nil
}

// ErrPortQuota means an exclusive or minimum allocation could not be satisfied.
var ErrPortQuota = errors.New("data port quota")

func overlaps(a1, a2, b1, b2 int) bool {
	return a1 <= b2 && b1 <= a2
}

// ForwardKey identifies a forward policy.
func ForwardKey(device, listen string) string {
	return device + "|" + listen
}

func deleteDeviceAccess(ctx context.Context, tx *sql.Tx, name string) error {
	prefix := name + "|"
	for _, table := range []string{"access_policies", "access_rules"} {
		_, err := tx.ExecContext(ctx, `
			DELETE FROM `+table+`
			WHERE (scope = 'device' AND scope_key = ?)
			   OR (scope = 'forward' AND substr(scope_key, 1, length(?)) = ?)`,
			name, prefix, prefix)
		if err != nil {
			return err
		}
	}
	return nil
}

// Revoke name-scoped list credentials before a deleted name can be reused.
func revokeDeviceQuickTokens(ctx context.Context, tx *sql.Tx, name string) error {
	result, err := tx.ExecContext(ctx, `UPDATE quick_tokens SET revoked = 1 WHERE device_name = ? AND revoked = 0`, name)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return insertAudit(ctx, tx, "quick_device_revoke", "success", name, time.Now().UTC().Format(time.RFC3339Nano))
}

// RecordRuntimeAssignments persists actual bindings only for the snapshot that
// was applied. A concurrent desired update must not have its decisions replaced.
func (db *DB) RecordRuntimeAssignments(ctx context.Context, revision int64, assignments []ports.Assignment) error {
	return db.Do(ctx, func(tx *sql.Tx) error {
		var desired int64
		if err := tx.QueryRowContext(ctx, "SELECT desired_revision FROM config_revisions WHERE domain = 'listener'").Scan(&desired); err != nil {
			return err
		}
		if desired != revision {
			return ErrRevisionConflict
		}
		want := map[[2]int64]string{}
		for _, item := range assignments {
			want[[2]int64{item.ForwardID, int64(item.Port)}] = item.State
		}
		rows, err := tx.QueryContext(ctx, "SELECT forward_id, port, state FROM data_assignments")
		if err != nil {
			return err
		}
		same, count := true, 0
		for rows.Next() {
			var id, port int64
			var state string
			if err := rows.Scan(&id, &port, &state); err != nil {
				rows.Close()
				return err
			}
			if want[[2]int64{id, port}] != state {
				same = false
			}
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if same && count == len(want) {
			return nil
		}
		return replaceAssignments(ctx, tx, assignments)
	})
}

// setManualDataPortsTx participates in the enclosing management mutation so
// candidate validation and allocation failures roll back the entire edit.
func setManualDataPortsTx(ctx context.Context, tx *sql.Tx, device, listen string, selected []int) error {
	if len(selected) > 200 {
		return ErrPortRange
	}
	var first, last, reserved int
	var id int64
	var useReserved int
	if err := tx.QueryRowContext(ctx, "SELECT data_first, data_last, reserved FROM port_settings WHERE id = 1").Scan(&first, &last, &reserved); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT f.id, f.use_reserved FROM weroxy_forwards f JOIN weroxy_devices d ON d.id=f.device_id WHERE d.name=? AND f.listen=?", device, listen).Scan(&id, &useReserved); err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, port := range selected {
		if port < first || port > last || (useReserved == 0 && port > last-reserved) || seen[port] {
			return ErrPortRange
		}
		seen[port] = true
	}
	if selected == nil {
		selected = []int{}
	}
	body, err := json.Marshal(selected)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE weroxy_forwards SET manual_data_ports=? WHERE id=?", string(body), id); err != nil {
		return err
	}
	return nil
}

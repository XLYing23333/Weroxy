// Package metrics counts forwarded business bytes in memory.
package metrics

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	// Up is bytes from the LAN target toward the public visitor.
	Up = "up"
	// Down is bytes from the public visitor toward the LAN target.
	Down = "down"
	// Legacy and Weroxy keep session ids in separate namespaces.
	Legacy = "legacy"
	Weroxy = "weroxy"
)

// Session is one business flow. Socket pairs are not separate sessions.
type Session struct {
	RunID          string
	Protocol       string
	ID             string
	DeviceID       int64
	ForwardID      int64
	Up             uint64
	Down           uint64
	Active         bool
	Device         string
	IP             string
	OS             string
	VisitorHidden  bool `json:"-"`
	visitorCounted bool
	Listen         string
	DataPort       int
	Started        time.Time
	ReadyAt        time.Time
	SetupMS        int64
	openedAt       time.Time
	Ended          time.Time
	Reason         string
	Last           time.Time
}

// Snapshot is a copy taken without the forwarder lock.
type Snapshot struct {
	GlobalUp          uint64
	GlobalDown        uint64
	Sessions          []Session
	Rejected          map[string]uint64
	Failures          map[string]uint64
	DeviceUp          map[int64]uint64
	DeviceDown        map[int64]uint64
	ForwardUp         map[int64]uint64
	ForwardDown       map[int64]uint64
	LegacyDeviceUp    map[int64]uint64
	LegacyDeviceDown  map[int64]uint64
	LegacyForwardUp   map[int64]uint64
	LegacyForwardDown map[int64]uint64
}

// Recent closed Session details are retained only for bounded operational views.
const maxClosedSessions = 1024

type closedSession struct {
	key  string
	item *Session
}

// Counters is the process-local business-byte table.
type Counters struct {
	visitors          map[visitorKey]*VisitorTotal
	visitorDirty      map[visitorKey]bool
	runID             string
	dirty             map[string]Session
	droppedDetails    uint64
	mu                sync.Mutex
	sessions          map[string]*Session
	closed            []closedSession
	rejected          map[string]uint64
	failures          map[string]uint64
	globalUp          uint64
	globalDown        uint64
	deviceUp          map[int64]uint64
	deviceDown        map[int64]uint64
	forwardUp         map[int64]uint64
	forwardDown       map[int64]uint64
	legacyDeviceUp    map[int64]uint64
	legacyDeviceDown  map[int64]uint64
	legacyForwardUp   map[int64]uint64
	legacyForwardDown map[int64]uint64
}

// New returns an empty table.
func New() *Counters {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return newCounters(strconv.FormatInt(time.Now().UnixNano(), 16))
	}
	return newCounters(hex.EncodeToString(raw[:]))
}

func newCounters(runID string) *Counters {
	return &Counters{
		visitors: map[visitorKey]*VisitorTotal{}, visitorDirty: map[visitorKey]bool{},
		runID: runID, dirty: map[string]Session{},
		sessions: map[string]*Session{}, rejected: map[string]uint64{}, failures: map[string]uint64{},
		deviceUp: map[int64]uint64{}, deviceDown: map[int64]uint64{},
		forwardUp: map[int64]uint64{}, forwardDown: map[int64]uint64{},
		legacyDeviceUp: map[int64]uint64{}, legacyDeviceDown: map[int64]uint64{},
		legacyForwardUp: map[int64]uint64{}, legacyForwardDown: map[int64]uint64{},
	}
}

func key(protocol, id string) string {
	return protocol + ":" + id
}

// Open records a session before bytes flow.
func (c *Counters) Open(protocol, id string, deviceID, forwardID int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.sessions[key(protocol, id)]
	if item == nil || !item.Active {
		now := time.Now()
		item = &Session{RunID: c.runID, Protocol: protocol, ID: id, DeviceID: deviceID, ForwardID: forwardID, Started: now.UTC(), openedAt: now}
		c.sessions[key(protocol, id)] = item
	}
	item.Active = true
	item.Last = time.Now().UTC()
	c.markDirtyLocked(item)
}

// Annotate stores the visitor identity seen when the session opened.
func (c *Counters) Annotate(protocol, id, device, ip, osName string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.sessions[key(protocol, id)]
	if item == nil {
		return
	}
	item.Device = device
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	item.IP = ip
	item.OS = osName
	c.noteVisitorLocked(item, 0)
	if item.Last.IsZero() {
		item.Last = time.Now().UTC()
	}
	c.markDirtyLocked(item)
}

// Add counts bytes that were actually written. Non-positive counts are ignored.
func (c *Counters) Add(protocol, id, direction string, n int) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.sessions[key(protocol, id)]
	if item == nil {
		return
	}
	item.Last = time.Now().UTC()
	c.noteVisitorLocked(item, uint64(n))
	defer c.markDirtyLocked(item)
	if direction == Up {
		item.Up += uint64(n)
		c.globalUp += uint64(n)
		if item.Protocol == Legacy {
			c.legacyDeviceUp[item.DeviceID] += uint64(n)
			c.legacyForwardUp[item.ForwardID] += uint64(n)
		} else {
			c.deviceUp[item.DeviceID] += uint64(n)
			c.forwardUp[item.ForwardID] += uint64(n)
		}
		return
	}
	if direction == Down {
		item.Down += uint64(n)
		c.globalDown += uint64(n)
		if item.Protocol == Legacy {
			c.legacyDeviceDown[item.DeviceID] += uint64(n)
			c.legacyForwardDown[item.ForwardID] += uint64(n)
		} else {
			c.deviceDown[item.DeviceID] += uint64(n)
			c.forwardDown[item.ForwardID] += uint64(n)
		}
	}
}

// MarkReady records the observed Session-creation-to-READY interval once. It can arrive
// just after a concurrent close; terminal status remains unchanged.
func (c *Counters) MarkReady(protocol, id string, at time.Time) {
	if c == nil || at.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.sessions[key(protocol, id)]
	if item == nil || !item.ReadyAt.IsZero() {
		return
	}
	start := item.openedAt
	if start.IsZero() {
		start = item.Started
	}
	elapsed := at.Sub(start)
	if elapsed < 0 {
		elapsed = 0
	}
	item.ReadyAt = at.UTC()
	item.SetupMS = elapsed.Milliseconds()
	if item.Last.Before(at) {
		item.Last = at.UTC()
	}
	c.markDirtyLocked(item)
}

// Close marks the session finished. Lifetime totals stay after detail eviction.
func (c *Counters) Close(protocol, id string) { c.CloseWithReason(protocol, id, "closed") }

// CloseWithReason records one terminal classification without logging traffic.
func (c *Counters) CloseWithReason(protocol, id, reason string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := key(protocol, id)
	if item := c.sessions[key]; item != nil && item.Active {
		item.Active = false
		item.Last = time.Now().UTC()
		item.Ended = item.Last
		item.Reason = reason
		if item.Protocol == Weroxy {
			if metric := failureMetric(reason); metric != "" {
				c.failures[metric]++
			}
		}
		c.markDirtyLocked(item)
		c.closed = append(c.closed, closedSession{key: key, item: item})
		if len(c.closed) > maxClosedSessions {
			old := c.closed[0]
			c.closed[0] = closedSession{}
			c.closed = c.closed[1:]
			if c.sessions[old.key] == old.item && !old.item.Active {
				delete(c.sessions, old.key)
			}
		}
	}
}

// failureMetric keeps the fault series bounded and separate from admission rejects.
func failureMetric(reason string) string {
	switch reason {
	case "client_data_unreachable":
		return "data_dial_failures"
	case "client_target_dial_failed":
		return "target_dial_failures"
	case "client_target_denied":
		return "target_denials"
	case "client_busy":
		return "client_busy"
	default:
		return ""
	}
}

// Visitor is one public address that has used a device.
type Visitor struct {
	IP                string `json:"ip"`
	OS                string `json:"os"`
	Active            bool   `json:"active"`
	Connections       int    `json:"connections"`
	Bytes             uint64 `json:"bytes"`
	Last              int64  `json:"last_unix"`
	ActiveConnections int    `json:"active_connections"`
	CumulativeSince   string `json:"cumulative_since"`
}

// Reject counts one admission refusal by a stable reason code.
func (c *Counters) Reject(reason string) {
	if c == nil || reason == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rejected[reason]++
}

// Snapshot copies independent lifetime totals and bounded Session details.
func (c *Counters) Snapshot() Snapshot {
	out := Snapshot{
		Rejected:   map[string]uint64{},
		Failures:   map[string]uint64{},
		DeviceUp:   map[int64]uint64{},
		DeviceDown: map[int64]uint64{},
		ForwardUp:  map[int64]uint64{}, ForwardDown: map[int64]uint64{},
		LegacyDeviceUp: map[int64]uint64{}, LegacyDeviceDown: map[int64]uint64{},
		LegacyForwardUp: map[int64]uint64{}, LegacyForwardDown: map[int64]uint64{},
	}
	if c == nil {
		return out
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for reason, n := range c.rejected {
		out.Rejected[reason] = n
	}
	for reason, n := range c.failures {
		out.Failures[reason] = n
	}
	out.GlobalUp, out.GlobalDown = c.globalUp, c.globalDown
	for id, n := range c.deviceUp {
		out.DeviceUp[id] = n
	}
	for id, n := range c.deviceDown {
		out.DeviceDown[id] = n
	}
	for id, n := range c.forwardUp {
		out.ForwardUp[id] = n
	}
	for id, n := range c.forwardDown {
		out.ForwardDown[id] = n
	}
	for id, n := range c.legacyDeviceUp {
		out.LegacyDeviceUp[id] = n
	}
	for id, n := range c.legacyDeviceDown {
		out.LegacyDeviceDown[id] = n
	}
	for id, n := range c.legacyForwardUp {
		out.LegacyForwardUp[id] = n
	}
	for id, n := range c.legacyForwardDown {
		out.LegacyForwardDown[id] = n
	}
	for _, item := range c.sessions {
		out.Sessions = append(out.Sessions, *item)
	}
	return out
}

// RestoreTotals seeds counters from the last durable sample before listeners
// start. Session details are deliberately not revived after a process restart.
func (c *Counters) RestoreTotals(saved Snapshot) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalUp, c.globalDown = saved.GlobalUp, saved.GlobalDown
	copyTotals := func(src map[int64]uint64) map[int64]uint64 {
		out := make(map[int64]uint64, len(src))
		for id, value := range src {
			out[id] = value
		}
		return out
	}
	c.deviceUp, c.deviceDown = copyTotals(saved.DeviceUp), copyTotals(saved.DeviceDown)
	c.forwardUp, c.forwardDown = copyTotals(saved.ForwardUp), copyTotals(saved.ForwardDown)
	c.legacyDeviceUp, c.legacyDeviceDown = copyTotals(saved.LegacyDeviceUp), copyTotals(saved.LegacyDeviceDown)
	c.legacyForwardUp, c.legacyForwardDown = copyTotals(saved.LegacyForwardUp), copyTotals(saved.LegacyForwardDown)
}

// TotalsSnapshot copies only lifetime counters for the periodic writer. It
// does not scan active or recently closed Session detail.
func (c *Counters) TotalsSnapshot() Snapshot {
	out := Snapshot{
		DeviceUp: map[int64]uint64{}, DeviceDown: map[int64]uint64{},
		ForwardUp: map[int64]uint64{}, ForwardDown: map[int64]uint64{},
		LegacyDeviceUp: map[int64]uint64{}, LegacyDeviceDown: map[int64]uint64{},
		LegacyForwardUp: map[int64]uint64{}, LegacyForwardDown: map[int64]uint64{},
	}
	if c == nil {
		return out
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out.GlobalUp, out.GlobalDown = c.globalUp, c.globalDown
	copyInto := func(dst, src map[int64]uint64) {
		for id, n := range src {
			dst[id] = n
		}
	}
	copyInto(out.DeviceUp, c.deviceUp)
	copyInto(out.DeviceDown, c.deviceDown)
	copyInto(out.ForwardUp, c.forwardUp)
	copyInto(out.ForwardDown, c.forwardDown)
	copyInto(out.LegacyDeviceUp, c.legacyDeviceUp)
	copyInto(out.LegacyDeviceDown, c.legacyDeviceDown)
	copyInto(out.LegacyForwardUp, c.legacyForwardUp)
	copyInto(out.LegacyForwardDown, c.legacyForwardDown)
	return out
}

// SetRoute records the listener snapshot and the selected Weroxy data port.
// Legacy has no separate dynamic data port and uses zero.
func (c *Counters) SetRoute(protocol, id, listen string, dataPort int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if item := c.sessions[key(protocol, id)]; item != nil {
		item.Listen, item.DataPort = listen, dataPort
		c.markDirtyLocked(item)
	}
}

const maxDirtyDetails = 8192

func (c *Counters) markDirtyLocked(item *Session) {
	key := key(item.Protocol, item.ID)
	if _, exists := c.dirty[key]; !exists && len(c.dirty) >= maxDirtyDetails {
		c.droppedDetails++
		return
	}
	c.dirty[key] = *item
}

// DrainDetails takes a bounded batch for the low-priority SQLite writer.
func (c *Counters) DrainDetails(limit int) []Session {
	if c == nil || limit < 1 {
		return nil
	}
	if limit > 512 {
		limit = 512
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Session, 0, limit)
	for key, item := range c.dirty {
		out = append(out, item)
		delete(c.dirty, key)
		if len(out) == limit {
			break
		}
	}
	return out
}

// RequeueDetails keeps the newest version if a bounded write fails.
func (c *Counters) RequeueDetails(items []Session) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range items {
		key := key(item.Protocol, item.ID)
		if current, ok := c.dirty[key]; ok && !current.Last.Before(item.Last) {
			continue
		}
		if _, ok := c.dirty[key]; !ok && len(c.dirty) >= maxDirtyDetails {
			c.droppedDetails++
			continue
		}
		c.dirty[key] = item
	}
}

// DetailBacklog reports the bounded in-memory persistence queue.
func (c *Counters) DetailBacklog() (queued int, dropped uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.dirty), c.droppedDetails
}

// PruneTotals evicts only durably saved totals for deleted, inactive entities.
// SQLite retains lifetime history; live flows and increments after the save survive.
func (c *Counters) PruneTotals(current, saved Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wd, wf, ld, lf := map[int64]bool{}, map[int64]bool{}, map[int64]bool{}, map[int64]bool{}
	for _, item := range c.sessions {
		if item.Active {
			if item.Protocol == Legacy {
				ld[item.DeviceID] = true
				lf[item.ForwardID] = true
			} else {
				wd[item.DeviceID] = true
				wf[item.ForwardID] = true
			}
		}
	}
	prune := func(totals, keep, durable map[int64]uint64, live map[int64]bool) {
		for id, value := range totals {
			_, configured := keep[id]
			savedValue, written := durable[id]
			if !configured && !live[id] && written && value <= savedValue {
				delete(totals, id)
			}
		}
	}
	prune(c.deviceUp, current.DeviceUp, saved.DeviceUp, wd)
	prune(c.deviceDown, current.DeviceDown, saved.DeviceDown, wd)
	prune(c.forwardUp, current.ForwardUp, saved.ForwardUp, wf)
	prune(c.forwardDown, current.ForwardDown, saved.ForwardDown, wf)
	prune(c.legacyDeviceUp, current.LegacyDeviceUp, saved.LegacyDeviceUp, ld)
	prune(c.legacyDeviceDown, current.LegacyDeviceDown, saved.LegacyDeviceDown, ld)
	prune(c.legacyForwardUp, current.LegacyForwardUp, saved.LegacyForwardUp, lf)
	prune(c.legacyForwardDown, current.LegacyForwardDown, saved.LegacyForwardDown, lf)
}

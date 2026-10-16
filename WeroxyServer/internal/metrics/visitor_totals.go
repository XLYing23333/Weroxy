package metrics

import (
	"net"
	"time"
)

type visitorKey struct {
	Protocol string
	DeviceID int64
	IP       string
}

// VisitorTotal is an absolute per-process checkpoint, independent of detail retention.
type VisitorTotal struct {
	RunID       string
	Protocol    string
	DeviceID    int64
	IP          string
	OS          string
	Connections uint64
	Bytes       uint64
	Version     uint64
	Last        int64
	Since       string
	Hidden      bool
}

const maxVisitorTotals = 8192

func (c *Counters) noteVisitorLocked(s *Session, bytes uint64) {
	if net.ParseIP(s.IP) == nil {
		return
	}
	k := visitorKey{s.Protocol, s.DeviceID, s.IP}
	v := c.visitors[k]
	if v == nil {
		if len(c.visitors) >= maxVisitorTotals {
			c.droppedDetails++
			return
		}
		v = &VisitorTotal{RunID: c.runID, Protocol: s.Protocol, DeviceID: s.DeviceID, IP: s.IP, Since: time.Now().UTC().Format(time.RFC3339Nano)}
		c.visitors[k] = v
	}
	if !s.visitorCounted {
		v.Connections++
		s.visitorCounted = true
		v.Hidden = false
	}
	v.Bytes += bytes
	v.OS = s.OS
	v.Last = time.Now().Unix()
	v.Version++
	c.visitorDirty[k] = true
}

func (c *Counters) VisitorTotals(protocol string, id int64) []VisitorTotal {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []VisitorTotal{}
	for k, v := range c.visitors {
		if k.Protocol == protocol && k.DeviceID == id {
			out = append(out, *v)
		}
	}
	return out
}

func (c *Counters) DrainVisitorTotals(limit int) []VisitorTotal {
	if c == nil || limit < 1 {
		return nil
	}
	if limit > 512 {
		limit = 512
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []VisitorTotal{}
	for k := range c.visitorDirty {
		out = append(out, *c.visitors[k])
		delete(c.visitorDirty, k)
		if len(out) == limit {
			break
		}
	}
	return out
}

func (c *Counters) RequeueVisitorTotals(items []VisitorTotal) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range items {
		k := visitorKey{v.Protocol, v.DeviceID, v.IP}
		if c.visitors[k] != nil {
			c.visitorDirty[k] = true
		}
	}
}

func (c *Counters) VisitorRunID() string {
	if c == nil {
		return ""
	}
	return c.runID
}

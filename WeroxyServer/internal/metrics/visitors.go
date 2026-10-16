package metrics

import "time"

// DeviceVisitors isolates protocols and stable IDs and never changes accounting.
func (c *Counters) DeviceVisitors(protocol string, deviceID int64) []Visitor {
	if c == nil {
		return []Visitor{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	grouped := map[string]*Visitor{}
	for _, s := range c.sessions {
		if s.Protocol != protocol || s.DeviceID != deviceID || s.IP == "" || s.VisitorHidden {
			continue
		}
		r := grouped[s.IP]
		if r == nil {
			r = &Visitor{IP: s.IP, OS: s.OS}
			grouped[s.IP] = r
		}
		if r.OS == "" {
			r.OS = s.OS
		}
		r.Connections++
		r.Bytes += s.Up + s.Down
		r.Active = r.Active || s.Active
		if s.Active {
			r.ActiveConnections++
		}
		if s.Last.Unix() > r.Last {
			r.Last = s.Last.Unix()
		}
	}
	out := make([]Visitor, 0, len(grouped))
	for _, r := range grouped {
		out = append(out, *r)
	}
	for i := 1; i < len(out); i++ {
		r := out[i]
		j := i
		for j > 0 && out[j-1].Last < r.Last {
			out[j] = out[j-1]
			j--
		}
		out[j] = r
	}
	return out
}

// DeleteVisitors marks existing bounded details only; any new session reappears.
func (c *Counters) DeleteVisitors(protocol string, deviceID int64, ips []string) (deleted, active []string) {
	deleted = []string{}
	active = []string{}
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	requested, busy := make(map[string]bool, len(ips)), make(map[string]bool, len(ips))
	for _, ip := range ips {
		requested[ip] = true
	}
	for _, session := range c.sessions {
		if session.Protocol == protocol && session.DeviceID == deviceID && requested[session.IP] && session.Active {
			busy[session.IP] = true
		}
	}
	for _, session := range c.sessions {
		if session.Protocol == protocol && session.DeviceID == deviceID && requested[session.IP] && !busy[session.IP] {
			session.VisitorHidden = true
		}
	}
	for _, ip := range ips {
		if busy[ip] {
			active = append(active, ip)
		} else {
			k := visitorKey{protocol, deviceID, ip}
			v := c.visitors[k]
			if v == nil && len(c.visitors) < maxVisitorTotals {
				v = &VisitorTotal{RunID: c.runID, Protocol: protocol, DeviceID: deviceID, IP: ip, Since: time.Now().UTC().Format(time.RFC3339Nano)}
				c.visitors[k] = v
			}
			if v != nil {
				v.Hidden = true
				v.Version++
				c.visitorDirty[k] = true
			}
			deleted = append(deleted, ip)
		}
	}
	return
}

func (c *Counters) RenameDevice(protocol string, id int64, name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		if s.Protocol == protocol && s.DeviceID == id {
			s.Device = name
			c.markDirtyLocked(s)
		}
	}
}

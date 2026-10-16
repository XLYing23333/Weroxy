package webui

import (
	"net"
	"net/netip"
	"sync"
)

const managementConnections = 128
const managementConnectionsPerIP = 16

// Admission precedes TLS: no unbounded goroutine or waiter is created for a
// refused socket. Entries disappear when the last admitted socket closes.
type budgetListener struct {
	net.Listener
	mu    sync.Mutex
	total int
	byIP  map[netip.Addr]int
}

func newBudgetListener(listener net.Listener) net.Listener {
	return &budgetListener{Listener: listener, byIP: make(map[netip.Addr]int)}
}
func (l *budgetListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		ip, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil {
			conn.Close()
			continue
		}
		ip = ip.Unmap().WithZone("")
		l.mu.Lock()
		allowed := l.total < managementConnections && l.byIP[ip] < managementConnectionsPerIP
		if allowed {
			l.total++
			l.byIP[ip]++
		}
		l.mu.Unlock()
		if !allowed {
			conn.Close()
			continue
		}
		return &budgetConnection{Conn: conn, release: func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			l.byIP[ip]--
			if l.byIP[ip] == 0 {
				delete(l.byIP, ip)
			}
		}}, nil
	}
}

type budgetConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *budgetConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

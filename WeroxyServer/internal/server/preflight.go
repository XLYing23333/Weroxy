package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"weroxy/server/internal/ports"
	"weroxy/server/internal/storage/sqlite"
)

// preflightListeners validates all declared entrances before any data-plane
// listener opens. The actual bind remains the authority if another process
// claims a port between this check and Listen.
func preflightListeners(ctx context.Context, db *sqlite.DB, cfg Config) error {
	if cfg.QuickList != "" {
		return errors.New("Quick List is served at --web /list; a separate --quick-list listener is unsupported")
	}
	claims, err := db.ListenClaims(ctx)
	if err != nil {
		return err
	}
	var occupied []ports.Endpoint
	for _, claim := range claims {
		if claim.Role == "forward" || claim.Role == "data" {
			occupied = append(occupied, claim)
		}
	}
	planned := []struct{ addr, role string }{
		{cfg.LegacyListen, "legacy"},
		{cfg.WeroxyControl, "weroxy-control"}, {cfg.WeroxyData, "weroxy-data"},
		{cfg.Web, "web"},
	}
	var entries []ports.Endpoint
	for _, item := range planned {
		if item.addr == "" {
			continue
		}
		host, portText, err := net.SplitHostPort(item.addr)
		if err != nil || host == "" {
			return fmt.Errorf("invalid %s listen address", item.role)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("invalid %s listen port", item.role)
		}
		entry := ports.Endpoint{Host: host, Port: port, Role: item.role}
		if hit, ok := ports.FirstConflict(occupied, entry); ok {
			return fmt.Errorf("%s listener conflicts with existing %s on port %d", item.role, hit.Role, hit.Port)
		}
		if hit, ok := ports.FirstConflict(entries, entry); ok {
			return fmt.Errorf("%s listener conflicts with %s on port %d", item.role, hit.Role, hit.Port)
		}
		entries = append(entries, entry)
	}

	return db.SetListenerReservations(ctx, entries)
}

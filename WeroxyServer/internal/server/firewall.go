package server

import (
	"context"
	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/firewallsync"
	"weroxy/server/internal/storage/sqlite"
)

type FirewallPlan = firewallsync.FirewallPlan

func PlanFirewall(ctx context.Context, db *sqlite.DB, endpoints []firewallagent.Endpoint) (FirewallPlan, error) {
	return firewallsync.PlanFirewall(ctx, db, endpoints)
}

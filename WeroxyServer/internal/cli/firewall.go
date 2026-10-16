package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/server"
	"weroxy/server/internal/storage/sqlite"
)

// firewallPlanCommand reads a temporary SQLite preview and asks the agent to
// compile a candidate script. Neither side mutates host or application state.
func firewallPlanCommand(args []string, opt Option) int {
	data, err := flagValue(args, "data", "/data")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	path := filepath.Join(data, "weroxy.db")
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintln(opt.Stderr, "Weroxy database not found")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	configPath, err := flagValue(args, "config", "")
	if err != nil {
		fmt.Fprintln(opt.Stderr, err)
		return 2
	}
	var endpoints []firewallagent.Endpoint
	var cfg firewallagent.Config
	if configPath != "" {
		cfg, err = firewallagent.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintln(opt.Stderr, "cannot read restricted agent config")
			return 1
		}
		endpoints = cfg.Endpoints
	} else {
		state, queryErr := firewallagent.Query(ctx)
		if queryErr != nil {
			fmt.Fprintln(opt.Stderr, "host firewall agent unavailable; no rules applied")
			return 1
		}
		endpoints = state.Endpoints
	}
	db, cleanup, err := sqlite.OpenPreview(path)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot preview Weroxy database")
		return 1
	}
	defer db.Close()
	defer cleanup()
	plan, err := server.PlanFirewall(ctx, db, endpoints)
	if err != nil {
		fmt.Fprintln(opt.Stderr, "cannot compile firewall candidate")
		return 1
	}
	var script string
	if configPath != "" {
		if err := firewallagent.ValidateRules(cfg, plan.Rules, time.Now().UTC()); err != nil {
			fmt.Fprintln(opt.Stderr, "agent config rejects firewall candidate; no rules applied")
			return 1
		}
		script = firewallagent.Script(cfg, plan.Rules)
	} else {
		response, err := firewallagent.Submit(ctx, firewallagent.Request{Operation: "plan", Rules: plan.Rules})
		if err != nil || response.Status != "planned" {
			fmt.Fprintln(opt.Stderr, "agent rejected firewall candidate; no rules applied")
			return 1
		}
		script = response.Script
	}
	fmt.Fprintf(opt.Stdout, "PREVIEW policy_revision=%d rules=%d matched_bans=%d unmatched_bans=%d\n",
		plan.PolicyRevision, len(plan.Rules), plan.MatchedBans, plan.UnmatchedBans)
	fmt.Fprint(opt.Stdout, script)
	return 0
}

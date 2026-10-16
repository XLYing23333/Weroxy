package firewallsync

import (
	"context"
	"errors"
	"time"

	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/storage/sqlite"
)

// Manager serializes bounded host work independently from control/forward locks.
type Manager struct {
	db   *sqlite.DB
	gate chan struct{}
}

func New(db *sqlite.DB) *Manager { return &Manager{db: db, gate: make(chan struct{}, 1)} }
func (m *Manager) Run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		_ = m.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (m *Manager) Reconcile(parent context.Context) error {
	select {
	case m.gate <- struct{}{}:
		defer func() { <-m.gate }()
	case <-parent.Done():
		return parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	s, err := m.db.FirewallSync(ctx)
	if err != nil {
		return err
	}
	if !s.Enabled && !s.Managed {
		if s.Status == "pending" {
			return m.db.RecordFirewallSync(ctx, "revoked", "", false)
		}
		return nil
	}
	fail := func(reason string) error {
		_ = m.db.RecordFirewallSync(ctx, "failed", reason, s.Managed)
		return errors.New(reason)
	}
	agent, err := firewallagent.Query(ctx)
	if err != nil {
		return fail("agent_unavailable")
	}
	var rules []firewallagent.Rule
	var matched, unmatched []int64
	revision, bans, forwards, err := m.db.FirewallSnapshot(ctx)
	if err != nil {
		return fail("snapshot_failed")
	}
	if s.Enabled {
		rules, matched, unmatched, err = CompileRules(bans, forwards, agent.Endpoints, time.Now().UTC())
		if err != nil {
			return fail("rule_budget_or_scope")
		}
		if agent.Digest == firewallagent.DigestRules(rules) && agent.KernelStatus == "agent_applied_unverified" {
			_ = m.db.RecordFirewallStatus(ctx, matched, "pending", revision, false)
			_ = m.db.RecordFirewallStatus(ctx, unmatched, "unsupported", revision, false)
			return m.db.RecordFirewallSync(ctx, "agent_applied_unverified", "", true)
		}
	}
	latest := agent.Generation
	if agent.PendingGeneration > latest {
		latest = agent.PendingGeneration
	}
	generation, err := m.db.ReserveFirewallGeneration(ctx, latest)
	if err != nil {
		return fail("generation_failed")
	}
	s.Managed = true
	operation := "apply"
	if !s.Enabled {
		operation = "revoke"
	}
	response, err := firewallagent.Submit(ctx, firewallagent.Request{Operation: operation, Generation: uint64(generation), Rules: rules})
	if err != nil || response.Status != "applied" {
		_ = m.db.RecordFirewallStatus(ctx, matched, "failed", revision, true)
		reason := "agent_apply_failed"
		if response.Reason == "apply_disabled" {
			reason = "agent_apply_disabled"
		}
		return fail(reason)
	}
	_ = m.db.RecordFirewallStatus(ctx, matched, "pending", revision, false)
	_ = m.db.RecordFirewallStatus(ctx, unmatched, "unsupported", revision, false)
	status := "agent_applied_unverified"
	if !s.Enabled {
		status = "revoked"
	}
	return m.db.RecordFirewallSync(ctx, status, "", s.Enabled)
}

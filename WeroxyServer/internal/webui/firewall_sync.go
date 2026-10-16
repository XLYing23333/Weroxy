package webui

import (
	"context"
	"net/http"
	"weroxy/server/internal/firewallagent"
	"weroxy/server/internal/firewallsync"
)

func (a *api) firewallSync(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		state, err := a.db.FirewallSync(r.Context())
		if err != nil {
			writeError(w, 500, "invalid")
			return
		}
		writeJSON(w, 200, state)
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if a.read(r, &body) != nil || body.Enabled == nil {
		writeError(w, 400, "invalid")
		return
	}
	if a.firewall == nil {
		writeError(w, 409, "unsupported")
		return
	}
	result, ok := a.mutateConfig(w, r, "policy", true, body, func(ctx context.Context) error { return a.db.SetFirewallSync(ctx, *body.Enabled) })
	if !ok {
		return
	}
	writeJSON(w, 200, mutationBody(result, map[string]any{"enabled": *body.Enabled, "kernel_status": "pending"}))
}
func (a *api) firewallPreview(w http.ResponseWriter, r *http.Request) {
	agent, err := firewallagent.Query(r.Context())
	if err != nil {
		writeError(w, 503, "agent_unavailable")
		return
	}
	plan, err := firewallsync.PlanFirewall(r.Context(), a.db, agent.Endpoints)
	if err != nil {
		writeError(w, 400, "invalid")
		return
	}
	response, err := firewallagent.Submit(r.Context(), firewallagent.Request{Operation: "plan", Rules: plan.Rules})
	if err != nil || response.Status != "planned" {
		writeError(w, 409, "unsupported")
		return
	}
	writeJSON(w, 200, map[string]any{"script": response.Script, "rules": len(plan.Rules), "matched_bans": plan.MatchedBans, "unmatched_bans": plan.UnmatchedBans, "policy_revision": plan.PolicyRevision})
}

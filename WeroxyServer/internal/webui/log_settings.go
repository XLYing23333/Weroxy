package webui

import (
	"context"
	"time"
)

func (a *api) reconcileLogs(ctx context.Context) {
	if a.log == nil {
		return
	}
	queryCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	s, err := a.db.LogSettings(queryCtx)
	if err != nil {
		return
	}
	if err := a.log.SetBudget(s.MaxFileMiB, s.MaxTotalMiB, s.MaxFiles, s.RetainDays); err != nil {
		_ = a.db.MarkConfigFailed(queryCtx, "logging", s.Revision, "log_budget_rejected")
		return
	}
	_ = a.db.MarkConfigApplied(queryCtx, "logging", s.Revision)
}
func (a *api) watchLogSettings(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reconcileLogs(ctx)
		}
	}
}

package webui

import (
	"context"
	"fmt"
	"os"

	"weroxy/server/internal/firewallagent"
)

// probeFirewall reports only what this process can prove. The application
// Guard and Docker publication are separate from host kernel enforcement.
func probeFirewall(contexts ...context.Context) map[string]string {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	if state, err := firewallagent.Query(ctx); err == nil {
		status := "unverified"
		if state.KernelStatus == "drift" {
			status = "drift"
		}
		return map[string]string{
			"status":     status,
			"reason":     "宿主机 agent 已连接，但内核规则仍需独立核验；agent generation 和应用层 Guard 分别报告。",
			"generation": fmt.Sprint(state.Generation),
			"rule_count": fmt.Sprint(state.Rules),
		}
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return map[string]string{
			"status": "unsupported",
			"reason": "宿主机防火墙 agent 尚未接入；容器内的应用 Guard 不等于宿主机内核规则。",
		}
	}
	return map[string]string{
		"status": "unsupported",
		"reason": "宿主机防火墙 agent 尚未接入；当前仅有应用层 Guard。",
	}
}

package status

// SafeState admits only fixed local status codes, never server text or secrets.
func SafeState(value string) string {
	switch value {
	case "connecting", "connected", "reconnecting", "dns_failed", "timeout", "rejected", "draining":
		return value
	}
	return "unknown"
}

func StateText(value string) string {
	switch SafeState(value) {
	case "connecting":
		return "正在连接"
	case "connected":
		return "已连接"
	case "reconnecting":
		return "连接中断，正在退避重连；请检查网络和服务端入口"
	case "dns_failed":
		return "DNS 解析失败；请检查 Server Host"
	case "timeout":
		return "连接超时；请检查端口发布及网络防火墙"
	case "rejected":
		return "凭据或协议版本被拒绝；请核对设备 Key 和客户端版本"
	case "draining":
		return "正在停止并排空连接"
	default:
		return "未连接；请使用 doctor 检查"
	}
}

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
		return "Connecting"
	case "connected":
		return "Connected"
	case "reconnecting":
		return "Connection interrupted; reconnecting with backoff. Check the network and Server entry point."
	case "dns_failed":
		return "DNS lookup failed; check Server Host."
	case "timeout":
		return "Connection timed out; check port publication and network firewall."
	case "rejected":
		return "Credentials or protocol version rejected; check the device Key and Client version."
	case "draining":
		return "Stopping and draining connections"
	default:
		return "Disconnected; use doctor to diagnose."
	}
}

package metrics

import "strings"

// GuessOS reads an HTTP User-Agent. A non-HTTP buffer returns an empty OS.
func GuessOS(buf []byte) string {
	text := string(buf)
	index := strings.Index(strings.ToLower(text), "user-agent:")
	if index < 0 {
		return ""
	}
	line := text[index+len("user-agent:"):]
	if end := strings.IndexAny(line, "\r\n"); end >= 0 {
		line = line[:end]
	}
	agent := strings.ToLower(line)
	switch {
	case strings.Contains(agent, "android"):
		return "android"
	case strings.Contains(agent, "iphone"), strings.Contains(agent, "ipad"), strings.Contains(agent, "ios"):
		return "ios"
	case strings.Contains(agent, "mac os"), strings.Contains(agent, "macintosh"):
		return "macos"
	case strings.Contains(agent, "windows"):
		return "windows"
	case strings.Contains(agent, "linux"):
		return "linux"
	default:
		return "unknown"
	}
}

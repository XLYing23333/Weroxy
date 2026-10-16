package sqlite

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var auditSecretPair = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|client[-_ ]?key|api[-_ ]?key)\s*[:=]\s*([^\s,"']+|"[^"]*"|'[^']*')`)

// Bound work before redaction as well as stored/output size. This is a defense
// against labeled secrets, not permission to pass raw credentials to auditing.
func auditText(value string, limit int) string {
	value = boundedAuditText(value, 8192)
	value = strings.ToValidUTF8(value, "�")
	value = auditSecretPair.ReplaceAllString(value, "$1=[redacted]")
	return boundedAuditText(value, limit)
}
func boundedAuditText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	end := limit - len("…")
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + "…"
}

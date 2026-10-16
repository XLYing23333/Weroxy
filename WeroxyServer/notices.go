// Package notices provides the third-party notices distributed with Weroxy.
package notices

import _ "embed"

//go:embed THIRD_PARTY_NOTICES
var text string

// Text returns the complete notices without accessing the filesystem.
func Text() string { return text }

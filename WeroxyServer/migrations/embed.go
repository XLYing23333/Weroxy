// Package migrations embeds versioned SQL for the server database.
package migrations

import "embed"

// FS contains the ordered schema files. Names start with a zero-padded version.
//
//go:embed *.sql
var FS embed.FS

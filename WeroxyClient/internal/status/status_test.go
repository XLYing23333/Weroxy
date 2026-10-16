package status

import (
	"path/filepath"
	"testing"
)

func TestPathForInstalledAndForegroundProfiles(t *testing.T) {
	if got := Path(InstalledConfigPath); got != InstalledStatusPath {
		t.Fatalf("installed status path=%q", got)
	}
	if got := Path("/tmp/weroxy-foreground/client.conf"); got != filepath.Join("/tmp/weroxy-foreground", "weroxy-client.status") {
		t.Fatalf("foreground status path=%q", got)
	}
}

package notices

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedNoticesCoverDeclaredGoModules(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	modules := regexp.MustCompile(`(?m)^\s*(?:require\s+)?([^\s()]+\.[^\s()]+)\s+(v[^\s]+)`).FindAllStringSubmatch(string(data), -1)
	for _, module := range modules {
		if !strings.Contains(Text(), module[1]+"@"+module[2]) {
			t.Fatalf("missing module %s", module[1])
		}
	}
	if !strings.Contains(Text(), "Go runtime and standard library") {
		t.Fatal("missing Go runtime notices")
	}
}

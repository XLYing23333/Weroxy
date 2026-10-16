package auth

import (
	"os"
	"testing"
)

func TestSetupCredentialPersistenceAndPermissions(t *testing.T) {
	dir := t.TempDir()
	a, err := SetupToken(dir)
	if err != nil || !ValidSetupToken(a) {
		t.Fatal("credential generation failed")
	}
	b, err := SetupToken(dir)
	if err != nil || a != b {
		t.Fatal("restart changed credential")
	}
	if !SetupMatches(a, b) || SetupMatches(a, "") || SetupMatches(a, a[:63]+"z") {
		t.Fatal("credential validation")
	}
	other, err := SetupToken(t.TempDir())
	if err != nil || a == other {
		t.Fatal("credential reused")
	}
	if err = os.Chmod(SetupPath(dir), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = SetupToken(dir); err == nil {
		t.Fatal("unsafe credential permissions accepted")
	}
}
func TestSharedUsernameValidation(t *testing.T) {
	for _, name := range []string{"", "with space", "名字", "root/../"} {
		if ValidUsername(name) {
			t.Fatal("unsafe username")
		}
	}
	if !ValidUsername("owner-A_1.test") {
		t.Fatal("valid username rejected")
	}
}

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxCredentialProviderCommandRunsBeforeRuntime(t *testing.T) {
	// Keep private fixtures under trusted ancestors and outside repository-wide
	// documentation scans. Production path validation stays intact.
	err := os.Mkdir("dist", 0o700)
	createdParent := err == nil
	if err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp("dist", ".provider-test-")
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(home); err != nil {
			t.Error(err)
		}
		if createdParent {
			_ = os.Remove("dist")
		}
	})
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	for _, tc := range []struct {
		args string
		code int
		want string
	}{
		{"codex auth provider", 1, "select a credential provider explicitly"},
		{"codex auth provider --select private-invalid-value", 1, "invalid credential provider choice"},
		{"codex auth provider --select file", 0, "Credential provider: file"},
		{"codex auth provider", 0, "Credential provider: file"},
		{"codex auth provider --select secret-service", 1, "a different credential provider is already selected"},
		{"codex auth provider", 0, "Credential provider: file"},
	} {
		var out, errOut bytes.Buffer
		// No target, credential registry, or Session dependencies are installed.
		code := (App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), strings.Fields(tc.args))
		if code != tc.code || !strings.Contains(out.String()+errOut.String(), tc.want) {
			t.Fatalf("%s = %d, stdout=%q stderr=%q", tc.args, code, out.String(), errOut.String())
		}
		if code == 0 && !strings.Contains(out.String(), "Linux credential operations and launches remain unavailable") {
			t.Fatal("selection implied Linux availability")
		}
		if strings.Contains(errOut.String(), "private-invalid-value") || strings.Contains(errOut.String(), home) {
			t.Fatal("selection failure disclosed private input")
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".acs")); !os.IsNotExist(err) {
		t.Fatalf("provider command touched runtime state: %v", err)
	}
	var output bytes.Buffer
	if handled, code := (App{ErrorOutput: &output}).RunUnsupportedExecution([]string{"codex", "auth", "login", "--name", "work"}); !handled || code != 1 {
		t.Fatalf("selected file provider enabled launch: (%v, %d)", handled, code)
	}
}

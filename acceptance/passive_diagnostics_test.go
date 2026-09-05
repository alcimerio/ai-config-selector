//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
)

func TestPromotedPassiveDiagnostics(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	bin := filepath.Join(home, "bin")
	for _, dir := range []string{bin, filepath.Join(home, ".acs", "profiles"), filepath.Join(home, ".agents", "skills", "selected")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"devin", "codex", "sw_vers", "sandbox-exec", "security"} {
		// Any accidental target, provider or PATH-based probe execution mutates home.
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nprintf executed > \"$HOME/executed\"\nexit 97\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".agents", "skills", "selected", "SKILL.md"), []byte("# private-manifest-sentinel-9281"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".acs", "profiles", "example.json"), []byte(`{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"selected"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotInspectionHome(t, home)
	run := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin, "TERM=dumb"}
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if stderr.Len() != 0 || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("streams: %s %s", &out, &stderr)
		}
		var r diagnostics.Result
		if json.Unmarshal(out.Bytes(), &r) != nil || r.FormatVersion != 1 || len(r.Checks) != 8 || code != r.ExitCode() {
			t.Fatalf("result: %d %s", code, &out)
		}
		for _, c := range r.Checks {
			if c.ID == "authentication" || c.ID == "runtime.enforcement" || c.ID == "executable.version" {
				if c.Status != "unchecked" {
					t.Fatalf("active claim: %+v", c)
				}
			}
		}
		if strings.Contains(out.String(), home) || strings.Contains(out.String(), "private-manifest-sentinel-9281") {
			t.Fatal("private data exposed")
		}
		return out.String(), code
	}
	for _, args := range [][]string{{"doctor", "--json"}, {"doctor", "--target", "devin", "--json"}, {"doctor", "--json", "--target", "codex-auth"}, {"doctor", "--target", "sandbox", "--json"}, {"profile", "validate", "example", "--json"}, {"profile", "validate", "--json", "example"}, {"profile", "validate", "missing", "--json"}, {"profile", "validate", "../private", "--json"}} {
		first, code := run(args...)
		again, _ := run(args...)
		if first != again {
			t.Fatal("nondeterministic JSON")
		}
		want := 0
		if (args[0] == "doctor" && runtime.GOOS != "darwin") || strings.Contains(strings.Join(args, " "), "missing") || strings.Contains(strings.Join(args, " "), "../") {
			want = 1
		}
		if code != want {
			t.Fatalf("%v: %d %s", args, code, first)
		}
	}
	if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
		t.Fatal("diagnostics changed bytes, modes, modification times or tree")
	}
	// No account, HOME, or optional clients are needed for a core-only check.
	cmd := exec.Command(binary, "doctor", "--json")
	cmd.Env = []string{"PATH=/nonexistent"}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if runtime.GOOS == "darwin" && err != nil {
		t.Fatalf("core without clients/account: %v %s", err, &out)
	}
	if !strings.Contains(out.String(), `"id":"executable.availability","status":"unchecked"`) || stderr.Len() != 0 {
		t.Fatalf("core: %s %s", &out, &stderr)
	}
}

package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxRejectsExecutionBeforeRuntimeComposition(t *testing.T) {
	for _, args := range [][]string{
		{"devin", "--profile", "missing"},
		{"codex", "--profile", "missing"},
		{"sandbox", "--profile", "missing"},
		{"run", "--profile", "missing", "--", "missing-executable"},
		{"codex", "auth", "login", "--name", "work"},
		{"codex", "auth", "login", "--name", "work", "--device-auth"},
		{"codex", "auth", "status", "--name", "work"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var output bytes.Buffer
			app := App{ErrorOutput: &output}
			handled, code := app.RunUnsupportedExecution(args)
			if runtime.GOARCH == "amd64" {
				if handled || code != 0 {
					t.Fatalf("qualified Linux execution = (%v, %d), want (false, 0)", handled, code)
				}
				return
			}
			if !handled || code != 1 {
				t.Fatalf("Linux execution = (%v, %d), want (true, 1)", handled, code)
			}
			for _, want := range []string{"Linux support requires native linux/amd64", "ACS never runs targets unsandboxed", "docs/design/linux-support.md"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("output %q does not contain %q", output.String(), want)
				}
			}
		})
	}
}

func TestLinuxKeepsNonExecutingCommandRoutes(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"doctor"}, {"profile", "list"},
		{"devin", "--help"},
		{"devin", "--profile", "example", "--dry-run"},
		{"codex", "--profile", "example", "--dry-run"},
		{"sandbox", "--profile", "example", "--dry-run"},
		{"run", "--profile", "example", "--dry-run", "--", "/bin/true"},
		{"codex", "auth", "list"},
		{"codex", "auth", "logout", "--name", "work"},
		{"devin", "--invalid"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if handled, code := (App{}).RunUnsupportedExecution(args); handled || code != 0 {
				t.Fatalf("non-executing route = (%v, %d)", handled, code)
			}
		})
	}
}

func TestLinuxDoctorExplainsUnavailableBackend(t *testing.T) {
	for _, args := range [][]string{{"doctor"}, {"doctor", "--json"}} {
		var output bytes.Buffer
		app := App{Output: &output}
		handled, code := app.RunDiagnostics(args, func() (string, error) {
			t.Fatal("doctor requested user home")
			return "", nil
		})
		if !handled || code != 0 {
			t.Fatalf("doctor = (%v, %d), want (true, 0); output %s", handled, code, output.String())
		}
		if !strings.Contains(output.String(), "supported_platform") {
			t.Fatalf("doctor output %q does not admit linux/amd64", output.String())
		}
	}
}

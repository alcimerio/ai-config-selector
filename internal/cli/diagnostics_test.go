package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
)

func TestDiagnosticsPublicGrammar(t *testing.T) {
	for _, args := range []string{"doctor --help", "help doctor", "profile validate --help", "help profile validate", "profile validate --json example --help"} {
		var out, stderr bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &stderr}).Run(context.Background(), strings.Fields(args))
		if code != 0 || !strings.Contains(out.String(), "Usage:") || stderr.Len() != 0 {
			t.Errorf("%s: %d %s %s", args, code, &out, &stderr)
		}
	}
	for _, args := range []string{"doctor --target", "doctor --target other", "doctor --target devin --target sandbox", "doctor --json --json", "doctor --target=devin", "doctor extra", "doctor --backend seatbelt", "doctor --active", "doctor -- --version", "profile validate", "profile validate example extra", "profile validate example --target devin", "profile validate example --json --json"} {
		var out, stderr bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &stderr}).Run(context.Background(), strings.Fields(args))
		if code != 1 || out.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("%s: %d %s %s", args, code, &out, &stderr)
		}
	}
}

func TestDiagnosticsMissingProfileIsStructured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range []string{"profile validate missing --json", "profile validate --json missing", "doctor --json", "doctor --json --target devin", "doctor --target sandbox --json", "doctor --target codex-auth --json"} {
		var out, stderr bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &stderr}).Run(context.Background(), strings.Fields(args))
		var result struct {
			FormatVersion int
			Checks        []struct{ ID, Status, Code, NextStep string }
		}
		if json.Unmarshal(out.Bytes(), &result) != nil || result.FormatVersion != 1 || len(result.Checks) == 0 || stderr.Len() != 0 {
			t.Fatalf("%s: %d %s %s", args, code, &out, &stderr)
		}
		for _, c := range result.Checks {
			if c.ID == "authentication" || c.ID == "runtime.enforcement" || c.ID == "executable.version" {
				if c.Status != "unchecked" {
					t.Fatalf("active claim: %+v", c)
				}
			}
		}
	}
}

func TestDiagnosticsEarlyDispatchAvoidsRuntime(t *testing.T) {
	home := t.TempDir()
	for _, args := range []string{"doctor --json", "profile validate missing --json", "profile validate ../private --json"} {
		var out, stderr bytes.Buffer
		forbidden := forbiddenInspectionRuntime{t}
		auth := &recordingCodexAuthRegistry{}
		app := cli.App{Profiles: forbidden, Planner: forbidden, SandboxPlanner: forbidden, Launcher: forbidden, SandboxLauncher: forbidden, CodexAuth: auth, Output: &out, ErrorOutput: &stderr, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("terminal checked"); return false }}
		handled, _ := app.RunDiagnostics(strings.Fields(args), func() (string, error) {
			if strings.HasPrefix(args, "doctor") || strings.Contains(args, "../") {
				t.Fatal("unexpected home discovery")
			}
			return home, nil
		})
		if !handled || stderr.Len() != 0 {
			t.Fatalf("%s: %s", args, &stderr)
		}
		if auth.loginCalls+auth.listCalls+auth.logoutCalls+auth.statusCalls+auth.recoverCalls != 0 {
			t.Fatal("provider called")
		}
	}
	for _, args := range []string{"doctor --help", "doctor --target unknown", "profile validate", "profile show example"} {
		handled, _ := (cli.App{}).RunDiagnostics(strings.Fields(args), func() (string, error) { t.Fatal("unexpected home"); return "", nil })
		if handled {
			t.Fatal("handled invalid or other command")
		}
	}
}

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestRunGrokProbesVersionBeforeCopyingCredentials(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".grok", "auth.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".grok", "mcp_credentials.json"), []byte("must-not-copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(t.TempDir(), "sessions")
	sandbox := &grokRecordingSandbox{version: "grok 1.0.62 (abc123)\n"}
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, "grok", authority.TargetRequirements{
		Recipe: authority.RecipeGrok, Executable: "grok", ExistingHomeDirectory: home, Semantics: authority.GrokSemantics(),
	})
	code, err := newExecutor(sandbox).RunGrok(context.Background(), GrokRequest{
		SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), ResolvedPlan: &plan,
		Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	})
	if err != nil || code != 0 {
		t.Fatalf("RunGrok = (%d, %v)", code, err)
	}
	if len(sandbox.requests) != 2 {
		t.Fatalf("processes = %d, want version probe then interactive", len(sandbox.requests))
	}
	if got := sandbox.requests[0].Arguments; len(got) != 1 || got[0] != "--version" || sandbox.requests[0].Environment != nil {
		t.Fatalf("version probe = %#v", sandbox.requests[0])
	}
	if len(sandbox.requests[1].Arguments) != 0 || sandbox.requests[1].Environment != nil {
		t.Fatalf("interactive invocation = %#v", sandbox.requests[1])
	}
	if sandbox.authAtProbe {
		t.Fatal("version probe saw credentials")
	}
	if sandbox.interactiveAuth != "{}\n" {
		t.Fatalf("interactive auth = %q", sandbox.interactiveAuth)
	}
	if sandbox.copiedMCPCredentials {
		t.Fatal("copied MCP credentials")
	}
	config := sandbox.interactiveConfig
	for _, want := range []string{"auto_update = false", `profile = "off"`, "skills = false", "sessions = false"} {
		if !strings.Contains(string(config), want) {
			t.Fatalf("config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(string(config), "folder_trust") {
		t.Fatalf("config used an unrecognized folder_trust key:\n%s", config)
	}
	if entries, err := os.ReadDir(sessions); err != nil || len(entries) != 0 {
		t.Fatalf("settled Grok Session remained: %v %v", entries, err)
	}
}

func TestRunGrokRejectsUnreviewedVersionBeforeCredentials(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".grok", "auth.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sandbox := &grokRecordingSandbox{version: "grok 1.0.61\n"}
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, "grok", authority.TargetRequirements{
		Recipe: authority.RecipeGrok, Executable: "grok", ExistingHomeDirectory: home, Semantics: authority.GrokSemantics(),
	})
	code, err := newExecutor(sandbox).RunGrok(context.Background(), GrokRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(), ResolvedPlan: &plan,
	})
	if code != 1 || !errors.Is(err, ErrGrokUnsupportedVersion) || len(sandbox.requests) != 1 {
		t.Fatalf("RunGrok = (%d, %v) processes=%d", code, err, len(sandbox.requests))
	}
	if sandbox.authAtProbe {
		t.Fatal("rejected version copied credentials")
	}
}

func TestRunGrokFailsClosedWithoutAuthentication(t *testing.T) {
	sandbox := &grokRecordingSandbox{version: "grok 1.0.62\n"}
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, "grok", authority.TargetRequirements{
		Recipe: authority.RecipeGrok, Executable: "grok", ExistingHomeDirectory: t.TempDir(), Semantics: authority.GrokSemantics(),
	})
	code, err := newExecutor(sandbox).RunGrok(context.Background(), GrokRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(), ResolvedPlan: &plan,
	})
	if code != 1 || !errors.Is(err, ErrGrokAuthenticationUnavailable) || len(sandbox.requests) != 1 {
		t.Fatalf("RunGrok = (%d, %v) processes=%d", code, err, len(sandbox.requests))
	}
}

func TestRunGrokRejectsControlEnvironmentBeforeSession(t *testing.T) {
	sandbox := &grokRecordingSandbox{version: "grok 1.0.62\n"}
	plan := authority.New([]authority.Contribution{{ID: "environment", Value: grokEnvContribution{destination: "GROK_HOME"}}}, launch.WorkspaceAccessReadOnly, "grok", authority.TargetRequirements{
		Recipe: authority.RecipeGrok, Executable: "grok", ExistingHomeDirectory: t.TempDir(), Semantics: authority.GrokSemantics(),
	})
	code, err := newExecutor(sandbox).RunGrok(context.Background(), GrokRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(), ResolvedPlan: &plan,
	})
	if code != 1 || !errors.Is(err, ErrGrokControlEnvironment) || sandbox.checks != 0 {
		t.Fatalf("RunGrok = (%d, %v) checks=%d", code, err, sandbox.checks)
	}
}

func TestGrokUserConfigLoadsOnReviewedCLI(t *testing.T) {
	binary := os.Getenv("ACS_TEST_GROK_BINARY")
	if binary == "" {
		t.Skip("ACS_TEST_GROK_BINARY is unset")
	}
	home := t.TempDir()
	config := grokUserConfiguration([]launch.MCPRecipe{{ID: "review", Disabled: []string{"remove_policy"}}}, binary, home)
	if err := os.MkdirAll(filepath.Join(home, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".grok", "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".grok", "config.toml"), []byte("[mcp_servers.evil]\ncommand = \"/bin/echo\"\nargs = [\"project\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "inspect", "--json")
	command.Dir = workspace
	command.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, output)
	}
	var inspected struct {
		ProjectTrusted bool `json:"projectTrusted"`
		ExternalCompat struct {
			Cells []struct {
				Enabled bool   `json:"enabled"`
				Source  string `json:"source"`
			} `json:"cells"`
		} `json:"externalCompat"`
	}
	if err := json.Unmarshal(output, &inspected); err != nil {
		t.Fatalf("inspect JSON: %v\n%s", err, output)
	}
	if inspected.ProjectTrusted {
		t.Fatalf("project scope was trusted:\n%s", output)
	}
	disabled := 0
	for _, cell := range inspected.ExternalCompat.Cells {
		if cell.Source == "config" && !cell.Enabled {
			disabled++
		}
		if cell.Enabled && cell.Source == "config" {
			t.Fatalf("compatibility cell stayed enabled:\n%s", output)
		}
	}
	if disabled == 0 {
		t.Fatalf("generated config did not disable compatibility cells:\n%s", output)
	}
}

type grokEnvContribution struct{ destination string }

func (grokEnvContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (grokEnvContribution) Materialize(string) error                         { return nil }
func (grokEnvContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (value grokEnvContribution) EnvironmentIntents() []launch.EnvironmentIntent {
	return []launch.EnvironmentIntent{{ID: "control", Destination: value.destination}}
}

type grokRecordingSandbox struct {
	requests             []launch.ProcessRequest
	version              string
	checks               int
	authAtProbe          bool
	interactiveAuth      string
	interactiveConfig    string
	copiedMCPCredentials bool
}

func (*grokRecordingSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (sandbox *grokRecordingSandbox) Check(context.Context, launch.SandboxCheck) error {
	sandbox.checks++
	return nil
}
func (sandbox *grokRecordingSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.requests = append(sandbox.requests, request)
	authPath := filepath.Join(request.SessionHome, ".grok", "auth.json")
	if len(sandbox.requests) == 1 {
		if _, err := os.Lstat(authPath); err == nil {
			sandbox.authAtProbe = true
		}
	} else {
		if auth, err := os.ReadFile(authPath); err == nil {
			sandbox.interactiveAuth = string(auth)
		}
		if config, err := os.ReadFile(filepath.Join(request.SessionHome, ".grok", "config.toml")); err == nil {
			sandbox.interactiveConfig = string(config)
		}
		if _, err := os.Lstat(filepath.Join(request.SessionHome, ".grok", "mcp_credentials.json")); err == nil {
			sandbox.copiedMCPCredentials = true
		}
	}
	process := &fakeProcess{}
	if len(sandbox.requests) == 1 {
		process.write = []byte(sandbox.version)
	}
	process.output = request.Terminal.Output
	return process, nil
}

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type executionMaterializer struct{}

func (executionMaterializer) Plan(context.Context, string, *launch.Plan) error { return nil }
func (executionMaterializer) Materialize(home string) error {
	return os.WriteFile(filepath.Join(home, "materialized"), []byte("yes"), 0o600)
}
func (executionMaterializer) Verify(context.Context, launch.VerificationContext) error { return nil }

func TestInteractiveCodexBindsOneIdentityBeforeSessionAndUsesFixedRecipe(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeLoginSandbox{version: SupportedCodexVersion}
	config := codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory, PrivateRoot: filepath.Join(root, "private")}
	if err := os.MkdirAll(config.PrivateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	registry.execution = newCodexExecutionRunner(config, sandbox)
	plan := authority.New([]authority.Contribution{{ID: "test", Value: executionMaterializer{}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	exitCode, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan})
	if err != nil || exitCode != 0 {
		t.Fatalf("execution = (%d, %v)", exitCode, err)
	}
	if len(sandbox.requests) != 2 {
		t.Fatalf("prepared processes = %d, want version plus interactive", len(sandbox.requests))
	}
	for _, request := range sandbox.requests {
		if request.WorkspaceAccess != launch.WorkspaceAccessReadOnly {
			t.Fatalf("workspace access = %q", request.WorkspaceAccess)
		}
		joined := strings.Join(request.Arguments, " ")
		for _, required := range []string{`cli_auth_credentials_store="file"`, `forced_login_method="chatgpt"`, `forced_chatgpt_workspace_id="workspace"`, `model_provider="openai"`, `sandbox_mode="read-only"`} {
			if !strings.Contains(joined, required) {
				t.Fatalf("arguments omit %q: %#v", required, request.Arguments)
			}
		}
	}
	if got := provider.records["work"].Auth; !reflect.DeepEqual(got, auth) || provider.replaceCalls != 0 {
		t.Fatalf("unchanged target replaced identity: replacements=%d auth=%q", provider.replaceCalls, got)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestInteractiveCodexFailsBeforeExecutableAndSessionForMissingIdentity(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	if err := provider.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: "/missing/codex", SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, &fakeLoginSandbox{})
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: "/missing/codex"}).WithAuthRef("work")
	if _, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); err == nil || !strings.Contains(err.Error(), ErrIdentityNotFound.Error()) {
		t.Fatalf("missing identity error = %v", err)
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("missing identity touched Sessions: %v", err)
	}
}

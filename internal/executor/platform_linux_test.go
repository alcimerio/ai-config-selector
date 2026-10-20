package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestLinuxLaunchFailsBeforeSessionCreation(t *testing.T) {
	for _, target := range []string{"shell", "devin", "devin verification", "grok"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			sessions := filepath.Join(root, "sessions")
			materializer := materializerFunc(func(string) error {
				t.Fatal("materialized a Session on Linux")
				return nil
			})
			executor := New()
			request := DevinRequest{
				SessionsDirectory: sessions, WorkingDirectory: t.TempDir(),
				Executable: "missing-devin", Materializer: materializer,
			}
			var err error
			switch target {
			case "shell":
				err = executor.RunShell(context.Background(), ShellRequest{
					SessionsDirectory: sessions, WorkingDirectory: request.WorkingDirectory,
					Materializer: materializer,
				})
			case "devin":
				_, err = executor.RunDevin(context.Background(), request)
			case "devin verification":
				err = executor.VerifyDevin(context.Background(), request)
			case "grok":
				plan := authority.New(nil, launch.WorkspaceAccessReadOnly, "grok", authority.TargetRequirements{Recipe: authority.RecipeGrok, Executable: "missing-grok", Semantics: authority.GrokSemantics()})
				_, err = executor.RunGrok(context.Background(), GrokRequest{SessionsDirectory: sessions, WorkingDirectory: request.WorkingDirectory, ResolvedPlan: &plan})
			}
			var failure *launch.SandboxError
			if !errors.As(err, &failure) || failure.Category != launch.SandboxUnsupportedPlatform {
				t.Fatalf("launch error = %v, want unsupported platform", err)
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatalf("failed launch created Session state: %v, %v", entries, err)
			}
		})
	}
}

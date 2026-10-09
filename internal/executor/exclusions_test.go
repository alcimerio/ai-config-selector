package executor

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type exclusionMaterial struct {
	intents []launch.PathExclusionIntent
	origins []string
}

func (m exclusionMaterial) PathExclusionIntents() []launch.PathExclusionIntent {
	return append([]launch.PathExclusionIntent(nil), m.intents...)
}
func (m exclusionMaterial) MaterialOrigins() []string                              { return append([]string(nil), m.origins...) }
func (exclusionMaterial) Materialize(string) error                                 { return nil }
func (exclusionMaterial) Verify(context.Context, launch.VerificationContext) error { return nil }
func (exclusionMaterial) Plan(context.Context, string, *launch.Plan) error         { return nil }

func TestExclusionsCommandCheckPrepareAndSourceConflict(t *testing.T) {
	workspace := t.TempDir()
	sessions := filepath.Join(t.TempDir(), "sessions")
	hidden := filepath.Join(workspace, "hidden")
	if err := os.Mkdir(hidden, 0700); err != nil {
		t.Fatal(err)
	}
	command, err := runcommand.Resolve(workspace, []string{"/bin/sh", "-c", "exit 0"})
	if err != nil {
		t.Fatal(err)
	}
	material := exclusionMaterial{intents: []launch.PathExclusionIntent{{ID: "hidden", Type: launch.PathTypeDirectory, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "hidden"}}}
	base := authority.New([]authority.Contribution{{ID: "exclusions", Value: material}}, launch.WorkspaceAccessReadWrite, 3, "")
	plan, err := base.ForCommand()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{process: &fakeProcess{}}
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Command: command})
	if err != nil || code != 0 {
		t.Fatalf("run=%d %v", code, err)
	}
	if len(sandbox.check.FilesystemExclusions) != 1 || !reflect.DeepEqual(sandbox.check.FilesystemExclusions, sandbox.request.FilesystemExclusions) {
		t.Fatal("check and attached policy differ")
	}
	// Captured Session policy remains independent of later contribution changes.
	material.intents[0].Path = "other"
	if !reflect.DeepEqual(sandbox.check.FilesystemExclusions, sandbox.request.FilesystemExclusions) {
		t.Fatal("captured policy mutated")
	}
	material.intents[0].Path = "hidden"
	material.origins = []string{hidden}
	conflict, err := authority.New([]authority.Contribution{{ID: "material", Value: material}}, launch.WorkspaceAccessReadWrite, 3, "").ForCommand()
	if err != nil {
		t.Fatal(err)
	}
	sandbox = &fakeSandbox{process: &fakeProcess{}}
	if _, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &conflict, Command: command}); err == nil || sandbox.prepares != 0 || sandbox.checks != 0 {
		t.Fatalf("source conflict started: %v checks=%d prepares=%d", err, sandbox.checks, sandbox.prepares)
	}
}

func TestExclusionsFixedRecipesCarryPolicyThroughEveryGeneration(t *testing.T) {
	for _, entrypoint := range []string{"shell", "devin", "verify-devin"} {
		t.Run(entrypoint, func(t *testing.T) {
			workspace := t.TempDir()
			sessions := filepath.Join(t.TempDir(), "sessions")
			if err := os.Mkdir(filepath.Join(workspace, "hidden"), 0700); err != nil {
				t.Fatal(err)
			}
			material := exclusionMaterial{intents: []launch.PathExclusionIntent{{ID: "hidden", Type: launch.PathTypeDirectory, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "hidden"}}}
			requirements := authority.TargetRequirements{Recipe: authority.RecipeDevin, Executable: "devin", Semantics: authority.DevinSemantics()}
			if entrypoint == "shell" {
				requirements = authority.TargetRequirements{Recipe: authority.RecipeShell, Executable: "/bin/zsh"}
			}
			plan := authority.New([]authority.Contribution{{ID: "exclusions", Value: material}}, launch.WorkspaceAccessReadOnly, 3, "devin", requirements)
			sandbox := &phaseMatrixSandbox{}
			runner := newExecutor(sandbox)
			terminal := launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}
			request := DevinRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, ExpectedCatalog: []skills.SkillReference{}, Terminal: terminal}
			var err error
			expected := 3
			switch entrypoint {
			case "shell":
				err = runner.RunShell(context.Background(), ShellRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Terminal: terminal})
				expected = 1
			case "verify-devin":
				err = runner.VerifyDevin(context.Background(), request)
				expected = 2
			default:
				_, err = runner.RunDevin(context.Background(), request)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(sandbox.check.FilesystemExclusions) != 1 || len(sandbox.requests) != expected {
				t.Fatalf("policy=%d processes=%d", len(sandbox.check.FilesystemExclusions), len(sandbox.requests))
			}
			for _, request := range sandbox.requests {
				if !reflect.DeepEqual(request.FilesystemExclusions, sandbox.check.FilesystemExclusions) {
					t.Fatal("preflight/attached policy differs from Check")
				}
			}
			phaseMatrixAssertEmpty(t, sessions)
		})
	}
}

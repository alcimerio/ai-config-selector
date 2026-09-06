package codex

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type recordingExecutor struct {
	calls   int
	request executor.CodexRequest
}

func (e *recordingExecutor) ExecuteCodex(_ context.Context, request executor.CodexRequest) (int, error) {
	e.calls++
	e.request = request
	return 0, nil
}

func TestCodexProjectionConsumesCommonSessionCopyAndPreservesSourceIdentity(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, ".agents", "skills", "review")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("selected"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &recordingExecutor{}
	adapter, err := New(Config{BinaryPath: "/usr/bin/codex", ExistingHomeDir: home, Executor: runtime})
	if err != nil {
		t.Fatal(err)
	}
	selection, _ := json.Marshal([]skills.SkillReference{{Source: "shared-agents", RelativePath: "review"}})
	workspace, _ := json.Marshal(map[string]string{"access": "read-only"})
	candidate := profile.Profile{Version: 3, SourceVersion: 3, Name: "example",
		Common:   map[string]profile.CommonPayload{"skills": {Version: 1, Selection: selection}, "workspace": {Version: 1, Selection: workspace}},
		Overlays: map[string]profile.OverlayPayload{"codex": {Version: 1, AuthRef: "work"}},
	}
	resolved, err := adapter.Categories().ResolveFor(context.Background(), candidate, "codex")
	if err != nil {
		t.Fatal(err)
	}
	sessionHome := t.TempDir()
	if err := resolved.Materialize(sessionHome); err != nil {
		t.Fatal(err)
	}
	projected := filepath.Join(sessionHome, ".codex", "skills", "shared-agents", "review", "SKILL.md")
	contents, err := os.ReadFile(projected)
	if err != nil || string(contents) != "selected" {
		t.Fatalf("projected contents = %q, %v", contents, err)
	}
	common := filepath.Join(sessionHome, ".acs", "common", "v1", "skills", "shared-agents", "review", "SKILL.md")
	if contents, err := os.ReadFile(common); err != nil || string(contents) != "selected" {
		t.Fatalf("common contents = %q, %v", contents, err)
	}
}

func TestCodexAuthOverrideIsResolvedOnceForPlanAndExecution(t *testing.T) {
	home := t.TempDir()
	runtime := &recordingExecutor{}
	adapter, err := New(Config{BinaryPath: "/usr/bin/codex", ExistingHomeDir: home, Executor: runtime})
	if err != nil {
		t.Fatal(err)
	}
	selection := json.RawMessage(`[]`)
	workspace := json.RawMessage(`{"access":"read-only"}`)
	candidate := profile.Profile{Version: 3, SourceVersion: 3, Name: "example",
		Common:   map[string]profile.CommonPayload{"skills": {Version: 1, Selection: selection}, "workspace": {Version: 1, Selection: workspace}},
		Overlays: map[string]profile.OverlayPayload{"codex": {Version: 1, AuthRef: "stored"}},
	}
	resolved, err := adapter.Categories().ResolveFor(context.Background(), candidate, "codex")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.PlanLaunch(context.Background(), home, resolved, "override")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, section := range plan.Sections {
		for _, item := range section.Items {
			for _, detail := range item.Details {
				found = found || (detail.Label == "reference" && detail.Value == "override")
				if strings.Contains(detail.Value, "stored") {
					t.Fatal("stored reference survived override")
				}
			}
		}
	}
	if !found {
		t.Fatalf("override absent from plan: %#v", plan)
	}
	if _, err := adapter.Launch(context.Background(), "ignored", home, resolved, "override", launch.Terminal{}); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 1 || runtime.request.ResolvedPlan == nil || runtime.request.ResolvedPlan.AuthRef() != "override" {
		t.Fatalf("execution request = %#v after %d calls", runtime.request, runtime.calls)
	}
}

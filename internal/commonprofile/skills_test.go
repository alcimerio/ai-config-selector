package commonprofile

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type testProjection struct {
	calls    int
	original string
	observed []byte
}

func (*testProjection) ID() string   { return "devin" }
func (*testProjection) Version() int { return 1 }
func (*testProjection) Expected(selected []skills.SkillBundle) ([]skills.SkillReference, error) {
	result := []skills.SkillReference{}
	for _, bundle := range selected {
		result = append(result, bundle.Reference)
	}
	return result, nil
}
func (*testProjection) Destination(home string, reference skills.SkillReference) (skills.SkillReference, string, error) {
	return reference, filepath.Join(home, "target", string(reference.Source), reference.RelativePath), nil
}
func (projection *testProjection) Materialize(home string, selected []skills.SkillBundle) error {
	projection.calls++
	if projection.original != "" {
		if err := os.WriteFile(filepath.Join(projection.original, "SKILL.md"), []byte("changed-host"), 0o600); err != nil {
			return err
		}
	}
	for _, bundle := range selected {
		data, err := os.ReadFile(filepath.Join(bundle.BundlePath, "SKILL.md"))
		if err != nil {
			return err
		}
		projection.observed = data
		_, destination, _ := projection.Destination(home, bundle.Reference)
		if err := os.MkdirAll(destination, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destination, "SKILL.md"), []byte("projected"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func TestResolvedCommonSkillsUseExactIdentityAndSelectedProjection(t *testing.T) {
	source := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("common"), 0o755); err != nil {
		t.Fatal(err)
	}
	reference := skills.SkillReference{Source: "shared-agents", RelativePath: "review"}
	catalog := []skills.SkillBundle{{Reference: reference, DisplayName: "review", BundlePath: source}}
	projection := &testProjection{original: source}
	skillsBinding, err := NewSkillsBinding(func(context.Context) ([]skills.SkillBundle, error) { return catalog, nil }, projection)
	if err != nil {
		t.Fatal(err)
	}
	workspaceBinding, err := NewWorkspaceBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", skillsBinding.Registration(), workspaceBinding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, skillsBinding, []skills.SkillReference{reference}); err != nil {
		t.Fatal(err)
	}
	candidate, err := registry.NewProfile("example", draft)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Version != profile.CurrentVersion || candidate.Target != "" || candidate.Common[SkillsCapabilityID].Version != 1 {
		t.Fatalf("v3 envelope = %#v", candidate)
	}

	shell, err := registry.ResolveFor(context.Background(), candidate, "")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := shell.Materialize(home); err != nil {
		t.Fatal(err)
	}
	common := filepath.Join(home, ".acs", "common", "v1", "skills", "shared-agents", "review", "SKILL.md")
	data, err := os.ReadFile(common)
	if err != nil || string(data) != "common" {
		t.Fatalf("common material = %q, %v", data, err)
	}
	if projection.calls != 0 {
		t.Fatal("shell selected target projection")
	}

	target, err := registry.ResolveFor(context.Background(), candidate, "devin")
	if err != nil {
		t.Fatal(err)
	}
	targetHome := t.TempDir()
	if err := target.Materialize(targetHome); err != nil {
		t.Fatal(err)
	}
	if projection.calls != 1 {
		t.Fatalf("projection calls = %d", projection.calls)
	}
	if string(projection.observed) != "common" {
		t.Fatalf("projection reread mutable host source: %q", projection.observed)
	}
	if !reflect.DeepEqual(target.DevinExpectedCatalog(), []skills.SkillReference{reference}) {
		t.Fatalf("expected catalog = %#v", target.DevinExpectedCatalog())
	}
}

func TestCommonDestinationRejectsCaseAndParentChildAliases(t *testing.T) {
	for _, selected := range [][]skills.SkillBundle{
		{{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "Review"}}, {Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "review"}}},
		{{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "review"}}, {Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "review/nested"}}},
		{{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "café"}}, {Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "café"}}},
	} {
		if err := ValidateCommonDestinations(selected); err == nil {
			t.Fatalf("accepted aliases %#v", selected)
		}
	}
}

func TestTargetOverlaySelectionIsExplicitAndFailsClosed(t *testing.T) {
	projection := &testProjection{}
	skillsBinding, err := NewSkillsBinding(func(context.Context) ([]skills.SkillBundle, error) { return []skills.SkillBundle{}, nil }, projection)
	if err != nil {
		t.Fatal(err)
	}
	workspaceBinding, err := NewWorkspaceBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", skillsBinding.Registration(), workspaceBinding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := registry.NewProfile("example", registry.NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	delete(candidate.Overlays, "devin")
	if _, err := registry.ResolveFor(context.Background(), candidate, ""); err != nil {
		t.Fatalf("shell selected an overlay: %v", err)
	}
	if _, err := registry.ResolveFor(context.Background(), candidate, "devin"); err == nil {
		t.Fatal("Devin accepted a missing selected overlay")
	}
	candidate.Overlays["devin"] = profile.OverlayPayload{Version: 2}
	if _, err := registry.ResolveFor(context.Background(), candidate, "devin"); err == nil {
		t.Fatal("Devin accepted an unsupported selected overlay")
	}
	candidate.Overlays = map[string]profile.OverlayPayload{"devin": {Version: 1}, "codex": {Version: 99}}
	if _, err := registry.ResolveFor(context.Background(), candidate, "devin"); err != nil {
		t.Fatalf("unknown inactive overlay widened or blocked Devin: %v", err)
	}
}

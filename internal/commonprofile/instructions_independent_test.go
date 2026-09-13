package commonprofile

import (
	"context"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type reviewInstructionProjection struct{ id string }

func (p reviewInstructionProjection) ID() string   { return p.id }
func (p reviewInstructionProjection) Version() int { return 1 }
func (p reviewInstructionProjection) Expected(b []instructions.Bundle) ([]instructions.Bundle, error) {
	return b, nil
}
func (p reviewInstructionProjection) Materialize(string, []instructions.Bundle) error { return nil }

func reviewInstructionProfile(t *testing.T, selected []instructions.Bundle) (*category.Registry, profile.Profile) {
	t.Helper()
	b, e := NewInstructionsBinding(func(context.Context, []instructions.Reference) ([]instructions.Bundle, error) { return selected, nil }, reviewInstructionProjection{"codex"})
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewSkillsBinding(func(context.Context) ([]skills.SkillBundle, error) { return []skills.SkillBundle{}, nil }, &testProjection{})
	if e != nil {
		t.Fatal(e)
	}
	w, e := NewWorkspaceBinding()
	if e != nil {
		t.Fatal(e)
	}
	r, e := category.NewRegistry("codex", s.Registration(), b.Registration(), w.Registration())
	if e != nil {
		t.Fatal(e)
	}
	d := r.NewDraft()
	refs := []instructions.Reference{}
	for _, v := range selected {
		refs = append(refs, v.Reference)
	}
	if e = category.SetSelection(&d, b, refs); e != nil {
		t.Fatal(e)
	}
	p, e := r.NewProfile("example", d)
	if e != nil {
		t.Fatal(e)
	}
	return r, p
}
func reviewBundle(name string) instructions.Bundle {
	return instructions.Bundle{Reference: instructions.Reference{Source: instructions.SourceID, RelativePath: name}, Content: []byte("original")}
}
func TestIndependentInstructionSyntaxKeepsIdentity(t *testing.T) {
	r, p := reviewInstructionProfile(t, []instructions.Bundle{reviewBundle("a.md"), reviewBundle("b.md")})
	plan, e := r.ResolveSyntaxFor(context.Background(), p, "codex")
	if e != nil {
		t.Fatalf("two valid syntax identities refused: %v", e)
	}
	if got := plan.DevinExpectedInstructions(); len(got) != 2 || got[0].Reference.RelativePath == "" {
		t.Fatalf("identity lost: %#v", got)
	}
}
func TestIndependentInstructionContributionOwnsInputSlice(t *testing.T) {
	selected := []instructions.Bundle{reviewBundle("a.md")}
	r, p := reviewInstructionProfile(t, selected)
	plan, e := r.ResolveFor(context.Background(), p, "")
	if e != nil {
		t.Fatal(e)
	}
	selected[0].Reference.RelativePath = "changed.md"
	selected[0].Content = []byte("tampered")
	home := t.TempDir()
	if e = plan.Materialize(home); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(home, ".acs/common/v1/instructions/acs-instructions/a.md"))
	if e != nil || string(data) != "original" {
		t.Fatalf("resolved input mutation changed plan: %q %v", data, e)
	}
}
func TestIndependentCodexInstructionPlanDoesNotClaimDevinProjection(t *testing.T) {
	r, p := reviewInstructionProfile(t, []instructions.Bundle{reviewBundle("a.md")})
	plan, e := r.ResolveFor(context.Background(), p, "codex")
	if e != nil {
		t.Fatal(e)
	}
	view, e := plan.Plan(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, section := range view.Sections {
		for _, item := range section.Items {
			for _, d := range item.Details {
				if strings.Contains(d.Value, ".devin/rules") {
					t.Fatalf("Codex falsely claims Devin projection: %#v", d)
				}
			}
		}
	}
}

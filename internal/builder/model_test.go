package builder

import (
	"context"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type testContribution struct{}

func (testContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (testContribution) Materialize(string) error                         { return nil }
func (testContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func TestModelCreatesProfileFromSelectedSkills(t *testing.T) {
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, testContribution]{
		ID:            "skills",
		SchemaVersion: 1,
		Empty:         func() []skills.SkillReference { return []skills.SkillReference{} },
		Resolve:       func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error) { return nil, nil },
		Contribute:    func([]skills.SkillBundle) (testContribution, error) { return testContribution{}, nil },
		Count:         func(selection []skills.SkillReference) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	bundle := skills.SkillBundle{
		Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
		DisplayName: "review",
		BundlePath:  "/global/review",
	}

	model := NewModel("reviews", registry.NewDraft(), binding, []skills.SkillBundle{bundle})
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))

	outcome := model.Outcome()
	if !outcome.Create || outcome.Cancelled {
		t.Fatalf("outcome = %#v, want a create outcome", outcome)
	}
	references, err := category.Selection(outcome.Draft, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0] != bundle.Reference {
		t.Fatalf("saved selection = %#v, want %#v", references, []skills.SkillReference{bundle.Reference})
	}
}

func TestModelRequiresConfirmationBeforeCreatingEmptyProfile(t *testing.T) {
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, testContribution]{
		ID:            "skills",
		SchemaVersion: 1,
		Empty:         func() []skills.SkillReference { return []skills.SkillReference{} },
		Resolve:       func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error) { return nil, nil },
		Contribute:    func([]skills.SkillBundle) (testContribution, error) { return testContribution{}, nil },
		Count:         func(selection []skills.SkillReference) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}

	model := NewModel("empty", registry.NewDraft(), binding, nil)
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if model.Outcome().Create {
		t.Fatal("empty Profile creation bypassed confirmation")
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if !model.Outcome().Create {
		t.Fatal("confirmed empty Profile did not create")
	}
}

func update(t *testing.T, model Model, message tea.Msg) Model {
	t.Helper()
	updated, _ := model.Update(message)
	return updated.(Model)
}

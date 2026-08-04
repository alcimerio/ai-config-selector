package builder

import (
	"context"
	"strconv"
	"strings"
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

	draft := registry.NewDraft()
	sameNamed := bundle
	sameNamed.Reference = skills.SkillReference{Source: "shared-agents", RelativePath: "review"}
	sameNamed.BundlePath = "/shared/review"
	model := NewModel("reviews", draft, NewSkillsEditor(draft, binding, []skills.SkillBundle{bundle, sameNamed}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if model.screen != skillsScreen {
		t.Fatal("Escape while search has focus returned to overview")
	}
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

	draft := registry.NewDraft()
	model := NewModel("empty", draft, NewSkillsEditor(draft, binding, nil))
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

func TestModelRetainsTerminalDimensionsAcrossInput(t *testing.T) {
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

	draft := registry.NewDraft()
	model := NewModel("dimensions", draft, NewSkillsEditor(draft, binding, nil))
	model = update(t, model, tea.WindowSizeMsg{Width: 120, Height: 40})
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	if model.width != 120 || model.height != 40 {
		t.Fatalf("dimensions = %dx%d, want 120x40", model.width, model.height)
	}
}

func TestModelOverviewListsEveryRegistryCategoryInOrder(t *testing.T) {
	skillsBinding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, testContribution]{
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
	notesBinding, err := category.Bind(category.Definition[[]string, string, testContribution]{
		ID:            "notes",
		SchemaVersion: 1,
		Empty:         func() []string { return []string{} },
		Resolve:       func(context.Context, []string) (string, error) { return "", nil },
		Contribute:    func(string) (testContribution, error) { return testContribution{}, nil },
		Count:         func(selection []string) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", skillsBinding.Registration(), notesBinding.Registration())
	if err != nil {
		t.Fatal(err)
	}

	draft := registry.NewDraft()
	view := NewModel("all-categories", draft, NewSkillsEditor(draft, skillsBinding, nil)).View().Content
	if !strings.Contains(view, "Skills                         0 selected\n  Notes                         0 selected") {
		t.Fatalf("overview does not preserve Registry category order:\n%s", view)
	}
}

func TestSkillsEditorRanksNameMatchesAndRetainsHiddenSelections(t *testing.T) {
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, testContribution]{
		ID: "skills", SchemaVersion: 1, Empty: func() []skills.SkillReference { return []skills.SkillReference{} },
		Resolve:    func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error) { return nil, nil },
		Contribute: func([]skills.SkillBundle) (testContribution, error) { return testContribution{}, nil },
		Count:      func(selection []skills.SkillReference) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	catalog := []skills.SkillBundle{
		{Reference: skills.SkillReference{Source: "source-post", RelativePath: "review"}, DisplayName: "review", BundlePath: "/global/review"},
		{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "post-path"}, DisplayName: "guide", BundlePath: "/global/post-path"},
		{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "post-archive"}, DisplayName: "post-archive", BundlePath: "/global/post-archive"},
	}
	draft := registry.NewDraft()
	editor := NewSkillsEditor(draft, binding, catalog)
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	editor = updated.(skillsEditor)
	updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	editor = updated.(skillsEditor)
	updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	editor = updated.(skillsEditor)
	for _, character := range "post" {
		updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: character, Text: string(character)}))
		editor = updated.(skillsEditor)
	}
	view := editor.View().Content
	if strings.Index(view, "post-archive") > strings.Index(view, "review") {
		t.Fatalf("display-name match did not rank first:\n%s", view)
	}
	updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	editor = updated.(skillsEditor)
	if editor.searchFocus || editor.query != "" {
		t.Fatalf("Escape did not clear and leave search: %#v", editor)
	}
	selected, err := category.Selection(editor.Draft(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0] != catalog[2].Reference {
		t.Fatalf("selection did not survive filtering: %#v", selected)
	}
	if !strings.Contains(editor.View().Content, "Skills                         1 selected") {
		t.Fatal("selected count disappeared after filtering")
	}
}

func TestSkillsEditorSanitizesDetailPathAndScalesToLargeCatalog(t *testing.T) {
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, testContribution]{
		ID: "skills", SchemaVersion: 1, Empty: func() []skills.SkillReference { return []skills.SkillReference{} },
		Resolve:    func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error) { return nil, nil },
		Contribute: func([]skills.SkillBundle) (testContribution, error) { return testContribution{}, nil },
		Count:      func(selection []skills.SkillReference) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	catalog := make([]skills.SkillBundle, 10_000)
	for index := range catalog {
		catalog[index] = skills.SkillBundle{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "skill" + strconv.Itoa(index)}, DisplayName: "skill" + strconv.Itoa(index), BundlePath: "/global/skill" + strconv.Itoa(index)}
	}
	catalog[0].BundlePath = "/global/unsafe\x1b[31m\npath"
	editor := NewSkillsEditor(registry.NewDraft(), binding, catalog)
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	editor = updated.(skillsEditor)
	updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	editor = updated.(skillsEditor)
	updated, _ = editor.Update(tea.KeyPressMsg(tea.Key{Code: '9', Text: "9"}))
	editor = updated.(skillsEditor)
	if len(editor.visible()) == 0 {
		t.Fatal("large catalog search returned no results")
	}
	view := NewSkillsEditor(registry.NewDraft(), binding, catalog).View().Content
	if strings.Contains(view, "\x1b") || strings.Contains(view, "unsafe\npath") {
		t.Fatal("detail output contains raw control characters")
	}
}

func update(t *testing.T, model Model, message tea.Msg) Model {
	t.Helper()
	updated, _ := model.Update(message)
	return updated.(Model)
}

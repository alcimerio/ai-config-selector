package builder

import (
	"context"
	"errors"
	"reflect"
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

func TestModelRunsOneImmutableSaveAndQuitsOnlyAfterSuccess(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	want := skills.SkillReference{Source: "devin-config", RelativePath: "review"}
	if err := category.SetSelection(&draft, binding, []skills.SkillReference{want}); err != nil {
		t.Fatal(err)
	}
	var saved category.Draft
	calls := 0
	model := NewModel("reviews", draft, NewSkillsEditor(draft, binding, nil)).WithSaver(func(_ context.Context, snapshot category.Draft) (string, error) {
		calls++
		saved = snapshot
		return "/profiles/reviews.json", nil
	})
	model.overviewCursor = len(model.categories())
	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if command == nil || model.screen != savingScreen || model.Outcome().Create {
		t.Fatalf("save start = screen %v, command %v, outcome %#v", model.screen, command, model.Outcome())
	}
	_, duplicate := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if duplicate != nil || calls != 0 {
		t.Fatalf("duplicate Create started work: command %v, calls %d", duplicate, calls)
	}
	if err := category.SetSelection(&model.draft, binding, []skills.SkillReference{{Source: "changed", RelativePath: "later"}}); err != nil {
		t.Fatal(err)
	}
	message := command()
	if calls != 1 {
		t.Fatalf("save calls = %d, want 1", calls)
	}
	model, quit := updateCommand(t, model, message)
	if quit == nil || !model.Outcome().Create || model.Outcome().Path != "/profiles/reviews.json" {
		t.Fatalf("successful outcome = %#v, quit %v", model.Outcome(), quit)
	}
	references, err := category.Selection(saved, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(references, []skills.SkillReference{want}) {
		t.Fatalf("saved snapshot = %#v, want %#v", references, []skills.SkillReference{want})
	}
}

func TestModelPreservesDraftAndRetriesAfterSanitizedSaveFailure(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	want := []skills.SkillReference{{Source: "devin-config", RelativePath: "review"}}
	calls := 0
	var snapshots []category.Draft
	model := NewModel("reviews", draft, NewSkillsEditor(draft, binding, nil)).WithSaver(func(_ context.Context, snapshot category.Draft) (string, error) {
		calls++
		snapshots = append(snapshots, snapshot)
		if calls == 1 {
			return "", errors.New("disk\n\x1b[31mfailed")
		}
		return "/profiles/reviews.json", nil
	})
	if err := category.SetSelection(&model.draft, binding, want); err != nil {
		t.Fatal(err)
	}
	model.editor = NewSkillsEditor(model.draft, binding, nil)
	model.overviewCursor = len(model.categories())
	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model, _ = updateCommand(t, model, command())
	view := model.View().Content
	if model.screen != saveFailureScreen || strings.Contains(view, "disk\n") || strings.Contains(view, "\x1b") || !strings.Contains(view, `disk\n\x1b[31mfailed`) {
		t.Fatalf("save failure was not recoverable and sanitized:\n%s", model.View().Content)
	}
	references, err := category.Selection(model.draft, binding)
	if err != nil || !reflect.DeepEqual(references, want) {
		t.Fatalf("draft after failure = %#v, %v", references, err)
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if model.screen != discardScreen {
		t.Fatal("save-failure Cancel did not enter discard confirmation")
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if model.screen != saveFailureScreen {
		t.Fatal("declining discard did not return to the save failure")
	}
	retrySelection := []skills.SkillReference{
		{Source: "devin-config", RelativePath: "review"},
		{Source: "shared-agents", RelativePath: "security"},
	}
	if err := category.SetSelection(&model.draft, binding, retrySelection); err != nil {
		t.Fatal(err)
	}
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'r', Text: "r"}))
	if command == nil || model.screen != savingScreen {
		t.Fatal("retry did not start a new save attempt")
	}
	if err := category.SetSelection(&model.draft, binding, []skills.SkillReference{{Source: "later", RelativePath: "mutation"}}); err != nil {
		t.Fatal(err)
	}
	model, _ = updateCommand(t, model, command())
	if calls != 2 || !model.Outcome().Create {
		t.Fatalf("retry calls = %d, outcome = %#v", calls, model.Outcome())
	}
	retried, err := category.Selection(snapshots[1], binding)
	if err != nil || !reflect.DeepEqual(retried, retrySelection) {
		t.Fatalf("retry snapshot = %#v, %v; want %#v", retried, err, retrySelection)
	}
}

func TestModelCtrlCCancelsAnUncommittedSaveBeforeDiscard(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	model := NewModel("cancel-save", draft, NewSkillsEditor(draft, binding, nil)).WithSaver(func(ctx context.Context, _ category.Draft) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	if err := category.SetSelection(&model.draft, binding, []skills.SkillReference{{Source: "devin-config", RelativePath: "review"}}); err != nil {
		t.Fatal(err)
	}
	model.overviewCursor = len(model.categories())
	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	if model.screen != cancellingSaveScreen {
		t.Fatal("Ctrl+C did not request cancellation of the active save")
	}
	model, _ = updateCommand(t, model, command())
	if model.screen != discardScreen {
		t.Fatal("cancelled save did not continue into the shared discard flow")
	}
	returnScreen := model.returnScreen
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	if model.returnScreen != returnScreen {
		t.Fatal("repeated Ctrl+C replaced the discard return state")
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if model.screen != overviewScreen {
		t.Fatalf("declining discard after save cancellation returned to screen %v", model.screen)
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	model, quit := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if quit == nil || !model.Outcome().Cancelled {
		t.Fatal("confirmed cancellation after save cancellation did not quit")
	}
}

func TestModelCancellationConfirmsOnlyChangedDraftsAndPreservesDeclinedChanges(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	empty := registry.NewDraft()
	unchanged := NewModel("unchanged", empty, NewSkillsEditor(empty, binding, nil))
	unchanged, quit := updateCommand(t, unchanged, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if quit == nil || !unchanged.Outcome().Cancelled {
		t.Fatal("unchanged overview Escape did not cancel immediately")
	}

	changed := NewModel("changed", empty, NewSkillsEditor(empty, binding, nil))
	selection := []skills.SkillReference{{Source: "devin-config", RelativePath: "review"}}
	if err := category.SetSelection(&changed.draft, binding, selection); err != nil {
		t.Fatal(err)
	}
	changed.editor = NewSkillsEditor(changed.draft, binding, nil)
	changed, quit = updateCommand(t, changed, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if quit != nil || changed.screen != discardScreen {
		t.Fatal("changed draft cancelled without discard confirmation")
	}
	changed, _ = updateCommand(t, changed, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if changed.screen != overviewScreen || changed.Outcome().Cancelled {
		t.Fatal("declining discard did not return to the prior screen")
	}
	kept, err := category.Selection(changed.draft, binding)
	if err != nil || !reflect.DeepEqual(kept, selection) {
		t.Fatalf("declined discard lost draft: %#v, %v", kept, err)
	}
	changed, _ = updateCommand(t, changed, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	if changed.screen != discardScreen {
		t.Fatal("Ctrl+C did not use the discard flow")
	}
	changed, quit = updateCommand(t, changed, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if quit == nil || !changed.Outcome().Cancelled {
		t.Fatal("confirmed discard did not cancel")
	}

	cancelRowDraft := registry.NewDraft()
	fromCancelRow := NewModel("cancel-row", cancelRowDraft, NewSkillsEditor(cancelRowDraft, binding, nil))
	if err := category.SetSelection(&fromCancelRow.draft, binding, selection); err != nil {
		t.Fatal(err)
	}
	fromCancelRow.overviewCursor = len(fromCancelRow.categories()) + 1
	fromCancelRow, quit = updateCommand(t, fromCancelRow, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if quit != nil || fromCancelRow.screen != discardScreen {
		t.Fatal("Cancel action did not use the changed-draft discard flow")
	}
}

func TestModelLazyDiscoveryDeduplicatesAndFailureBackReturnsToOverview(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	calls := 0
	model := NewModel("lazy", draft, NewSkillsEditor(draft, binding), func(context.Context) ([]skills.SkillBundle, error) {
		calls++
		return nil, errors.New("offline")
	})
	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if command == nil || model.screen != loadingScreen {
		t.Fatal("opening unloaded Skills did not enter loading")
	}
	_, duplicate := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if duplicate != nil {
		t.Fatal("loading accepted a duplicate discovery request")
	}
	model, _ = updateCommand(t, model, command())
	if calls != 1 || model.screen != loadFailureScreen {
		t.Fatalf("discovery failure = calls %d, screen %v", calls, model.screen)
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if model.screen != overviewScreen || model.Outcome().Cancelled {
		t.Fatal("failure Back cancelled the Profile Builder")
	}
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if command == nil || model.screen != loadingScreen {
		t.Fatal("reopening failed Skills did not retry discovery")
	}
}

func newBuilderFixture(t *testing.T) (category.Binding[[]skills.SkillReference, []skills.SkillBundle, testContribution], *category.Registry) {
	t.Helper()
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
	return binding, registry
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
	if !strings.Contains(view, "Backspace delete") {
		t.Fatal("search footer omits an active key")
	}
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

func updateCommand(t *testing.T, model Model, message tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	updated, command := model.Update(message)
	return updated.(Model), command
}

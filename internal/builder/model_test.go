package builder

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

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
	model := newLoadedSkillsModel(t, "reviews", draft, registry, binding, []skills.SkillBundle{bundle, sameNamed})
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if model.screen != categoryScreen {
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
	model := newLoadedSkillsModel(t, "empty", draft, registry, binding, nil)
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
	model := newLoadedSkillsModel(t, "dimensions", draft, registry, binding, nil)
	model = update(t, model, tea.WindowSizeMsg{Width: 120, Height: 40})
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	if model.width != 120 || model.height != 40 {
		t.Fatalf("dimensions = %dx%d, want 120x40", model.width, model.height)
	}
}

func TestModelSmallTerminalRetainsStateAndResizeRestoresActiveScreen(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	catalog := []skills.SkillBundle{{
		Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
		DisplayName: "review", BundlePath: "/global/review",
	}}
	model := newLoadedSkillsModel(t, "sizes", draft, registry, binding, catalog)
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	model = update(t, model, tea.WindowSizeMsg{Width: MinimumWidth - 1, Height: MinimumHeight - 1})
	if !strings.Contains(model.View().Content, "Terminal too small") {
		t.Fatalf("small-terminal view = %q", model.View().Content)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model = update(t, model, tea.WindowSizeMsg{Width: MinimumWidth, Height: MinimumHeight})
	if model.screen != categoryScreen || !strings.Contains(model.View().Content, "Skills                         1 selected") {
		t.Fatalf("resize did not restore Skills state:\n%s", model.View().Content)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	lines := strings.Split(model.View().Content, "\n")
	if len(lines) > MinimumHeight {
		t.Fatalf("minimum-size Skills view uses %d rows, want at most %d:\n%s", len(lines), MinimumHeight, model.View().Content)
	}
	for _, line := range lines {
		if len([]rune(line)) > MinimumWidth {
			t.Fatalf("minimum-size Skills line uses %d columns, want at most %d: %q", len([]rune(line)), MinimumWidth, line)
		}
	}
	references, err := category.Selection(model.draft, binding)
	if err != nil || !reflect.DeepEqual(references, []skills.SkillReference{catalog[0].Reference}) {
		t.Fatalf("resize lost Draft selection: %#v, %v", references, err)
	}
}

func TestModelContextualPresentationUsesTextAndSymbolsWithoutColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	model := newLoadedSkillsModel(t, "presentation", draft, registry, binding, []skills.SkillBundle{{
		Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
		DisplayName: "review", BundlePath: "/global/review",
	}})

	cases := []struct {
		name   string
		screen screen
		want   []string
	}{
		{name: "overview", screen: overviewScreen, want: []string{"> Skills", "Up/Down navigate", "Esc cancel", "Ctrl+C cancel"}},
		{name: "loading", screen: loadingScreen, want: []string{"Loading Skills...", "Ctrl+C cancel"}},
		{name: "load failure", screen: loadFailureScreen, want: []string{"Error: Skills", "R/Enter/Space retry", "Left/Esc back", "Ctrl+C cancel"}},
		{name: "empty confirmation", screen: confirmScreen, want: []string{"Confirm:", "Y/Enter create", "N/Esc/Left return", "Ctrl+C cancel"}},
		{name: "saving", screen: savingScreen, want: []string{"Saving Profile...", "Ctrl+C cancel save"}},
		{name: "save failure", screen: saveFailureScreen, want: []string{"Error: Profile", "R/Enter/Space retry", "Esc cancel", "Ctrl+C cancel"}},
		{name: "discard", screen: discardScreen, want: []string{"Confirm:", "Y/Enter discard", "N/Esc/Left keep editing"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			current := model
			current.screen = test.screen
			current.saveError = errors.New("disk failed")
			view := current.View().Content
			if strings.Contains(view, "\x1b[") {
				t.Fatalf("NO_COLOR view contains ANSI: %q", view)
			}
			for _, want := range test.want {
				if !strings.Contains(view, want) {
					t.Errorf("view omits %q:\n%s", want, view)
				}
			}
		})
	}
}

func TestMinimumWidthConstrainsMaximumNamesCatalogTextAndErrors(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	long := strings.Repeat("界", 80)
	model := newLoadedSkillsModel(t, strings.Repeat("n", 64), draft, registry, binding, []skills.SkillBundle{{
		Reference:   skills.SkillReference{Source: skills.Source(long), RelativePath: long},
		DisplayName: long, BundlePath: "/" + long,
	}})
	model = update(t, model, tea.WindowSizeMsg{Width: MinimumWidth, Height: MinimumHeight})
	model.saveError = errors.New(long)
	for _, currentScreen := range []screen{overviewScreen, categoryScreen, saveFailureScreen} {
		model.screen = currentScreen
		view := model.View().Content
		lines := strings.Split(view, "\n")
		if len(lines) > MinimumHeight {
			t.Errorf("screen %v uses %d rows at minimum size:\n%s", currentScreen, len(lines), view)
		}
		for _, line := range lines {
			if width := ansi.StringWidth(line); width > MinimumWidth {
				t.Errorf("screen %v line uses %d columns at minimum size: %q", currentScreen, width, line)
			}
		}
	}
}

func TestSmallTerminalShowsOnlyControlsValidForTheHiddenState(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	model := newLoadedSkillsModel(t, "small-modal", draft, registry, binding, nil)
	model = update(t, model, tea.WindowSizeMsg{Width: MinimumWidth - 1, Height: MinimumHeight - 1})
	model.screen = discardScreen
	if view := model.View().Content; strings.Contains(view, "Ctrl+C") || !strings.Contains(view, "Resize the terminal to continue") {
		t.Fatalf("discard resize controls are not contextual: %q", view)
	}
	model.screen = savingScreen
	if view := model.View().Content; !strings.Contains(view, "Ctrl+C cancel save") {
		t.Fatalf("saving resize controls are not contextual: %q", view)
	}
}

func TestInjectedRuntimeOwnsOneAlternateScreenAndReturnsNormalizedOutput(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	var output bytes.Buffer
	input, writer := io.Pipe()
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = writer.Write([]byte("\x03"))
		_ = writer.Close()
	}()
	program := tea.NewProgram(
		newLoadedSkillsModel(t, "runtime", draft, registry, binding, nil),
		tea.WithInput(input), tea.WithOutput(&output),
		tea.WithWindowSize(80, 24),
		tea.WithEnvironment([]string{"TERM=xterm-256color", "NO_COLOR=1"}),
	)
	outcome, err := finishRuntime(program)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Cancelled {
		t.Fatalf("runtime outcome = %#v", outcome)
	}
	raw := output.String()
	if strings.Count(raw, "\x1b[?1049h") != 1 || strings.Count(raw, "\x1b[?1049l") != 1 {
		t.Fatalf("alternate-screen transitions = %q", raw)
	}
	normalized := ansi.Strip(raw)
	if !strings.Contains(normalized, "Create Profile") {
		t.Fatalf("raw runtime output = %q; normalized = %q", raw, normalized)
	}
}

func TestRunPropagatesInjectedRuntimeError(t *testing.T) {
	want := errors.New("runtime failed")
	if _, err := finishRuntime(failingRuntime{err: want}); !errors.Is(err, want) {
		t.Fatalf("runtime error = %v, want %v", err, want)
	}
}

type failingRuntime struct{ err error }

func (runtime failingRuntime) Run() (tea.Model, error) { return nil, runtime.err }

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
	skillsRegistration, err := RegisterSkillsEditor(skillsBinding, func(context.Context) ([]skills.SkillBundle, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	notesRegistration := mustEditorRegistration(t, EditorDefinition[registryDiscovery]{
		ID: "notes", Category: notesBinding.Registration(),
		New:      func(draft category.Draft) Editor { return registryEditor{draft: draft} },
		Discover: func(context.Context) (registryDiscovery, error) { return registryDiscovery{}, nil },
		Loaded:   func(editor Editor, _ registryDiscovery) (Editor, error) { return editor, nil },
	})
	editors, err := NewEditorRegistry(registry, skillsRegistration, notesRegistration)
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewModel("all-categories", draft, editors)
	if err != nil {
		t.Fatal(err)
	}
	view := model.View().Content
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
	model := newLoadedSkillsModel(t, "reviews", draft, registry, binding, nil).WithSaver(func(_ context.Context, snapshot category.Draft) (string, error) {
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
	model := newLoadedSkillsModel(t, "reviews", draft, registry, binding, nil).WithSaver(func(_ context.Context, snapshot category.Draft) (string, error) {
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
	model.editors[0].editor = NewSkillsEditor(model.draft, binding, nil)
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
	model := newLoadedSkillsModel(t, "cancel-save", draft, registry, binding, nil).WithSaver(func(ctx context.Context, _ category.Draft) (string, error) {
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
	unchanged := newLoadedSkillsModel(t, "unchanged", empty, registry, binding, nil)
	unchanged, quit := updateCommand(t, unchanged, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if quit == nil || !unchanged.Outcome().Cancelled {
		t.Fatal("unchanged overview Escape did not cancel immediately")
	}

	changed := newLoadedSkillsModel(t, "changed", empty, registry, binding, nil)
	selection := []skills.SkillReference{{Source: "devin-config", RelativePath: "review"}}
	if err := category.SetSelection(&changed.draft, binding, selection); err != nil {
		t.Fatal(err)
	}
	changed.editors[0].editor = NewSkillsEditor(changed.draft, binding, nil)
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
	fromCancelRow := newLoadedSkillsModel(t, "cancel-row", cancelRowDraft, registry, binding, nil)
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
	model := newLazySkillsModel(t, "lazy", draft, registry, binding, func(context.Context) ([]skills.SkillBundle, error) {
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

func newLazySkillsModel(t *testing.T, name string, draft category.Draft, categories *category.Registry, binding category.Binding[[]skills.SkillReference, []skills.SkillBundle, testContribution], discover func(context.Context) ([]skills.SkillBundle, error)) Model {
	t.Helper()
	registration, err := RegisterSkillsEditor(binding, discover)
	if err != nil {
		t.Fatal(err)
	}
	editors, err := NewEditorRegistry(categories, registration)
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewModel(name, draft, editors)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func newLoadedSkillsModel(t *testing.T, name string, draft category.Draft, categories *category.Registry, binding category.Binding[[]skills.SkillReference, []skills.SkillBundle, testContribution], catalog []skills.SkillBundle) Model {
	t.Helper()
	model := newLazySkillsModel(t, name, draft, categories, binding, func(context.Context) ([]skills.SkillBundle, error) { return catalog, nil })
	model.editors[0].editor = NewSkillsEditor(draft, binding, catalog)
	model.editors[0].loadState = loaded
	return model
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

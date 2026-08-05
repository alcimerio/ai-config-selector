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
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type switchSelection struct {
	Codes []int `json:"codes"`
}

type switchResolved struct {
	Labels []string
}

type switchOption struct {
	Code  int
	Label string
}

type switchDiscovery struct {
	Options []switchOption
}

type launchCalls struct {
	materialized int
	verified     int
}

type switchContribution struct {
	resolved switchResolved
	calls    *launchCalls
}

func (contribution switchContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	items := make([]launch.PlanItem, 0, len(contribution.resolved.Labels))
	for _, label := range contribution.resolved.Labels {
		items = append(items, launch.PlanItem{Label: label})
	}
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Feature switches:", Items: items})
	return nil
}
func (contribution switchContribution) Materialize(string) error {
	contribution.calls.materialized++
	return nil
}
func (contribution switchContribution) Verify(context.Context, launch.VerificationContext) error {
	contribution.calls.verified++
	return nil
}

type skillPlanContribution struct{ selected []skills.SkillBundle }

func (contribution skillPlanContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	items := make([]launch.PlanItem, 0, len(contribution.selected))
	for _, bundle := range contribution.selected {
		items = append(items, launch.PlanItem{Label: bundle.DisplayName})
	}
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Test Skills:", Items: items})
	return nil
}
func (skillPlanContribution) Materialize(string) error { return nil }
func (skillPlanContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

type switchEditor struct {
	draft   category.Draft
	binding category.Binding[switchSelection, switchResolved, switchContribution]
	options []switchOption
	query   string
	cursor  int
	scroll  int
}

func (editor switchEditor) Init() tea.Cmd { return nil }
func (editor switchEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return editor, nil
	}
	switch press.String() {
	case "down":
		if editor.cursor < len(editor.options)-1 {
			editor.cursor++
			editor.scroll = editor.cursor
		}
	case "space", "enter":
		if len(editor.options) != 0 {
			selection, _ := category.Selection(editor.draft, editor.binding)
			selection.Codes = []int{editor.options[editor.cursor].Code}
			_ = category.SetSelection(&editor.draft, editor.binding, selection)
		}
	default:
		if press.Key().Text != "" {
			editor.query += press.Key().Text
		}
	}
	return editor, nil
}
func (editor switchEditor) View() tea.View {
	selection, _ := category.Selection(editor.draft, editor.binding)
	return tea.NewView("Switches\nquery=" + editor.query + " cursor=" + strconv.Itoa(editor.cursor) + " scroll=" + strconv.Itoa(editor.scroll) + " selected=" + switchCodes(selection.Codes))
}
func (editor switchEditor) Draft() category.Draft { return editor.draft }
func (editor switchEditor) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	return editor
}
func (switchEditor) ListFocused() bool { return true }

func switchCodes(codes []int) string {
	if len(codes) == 0 {
		return "none"
	}
	return strconv.Itoa(codes[0])
}

type multiCategoryFixture struct {
	categories    *category.Registry
	editors       *EditorRegistry
	skillsBinding category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillPlanContribution]
	switchBinding category.Binding[switchSelection, switchResolved, switchContribution]
	calls         *launchCalls
}

func newMultiCategoryFixture(t *testing.T, discoverSkills func(context.Context) ([]skills.SkillBundle, error), discoverSwitches func(context.Context) (switchDiscovery, error)) multiCategoryFixture {
	t.Helper()
	skillsBinding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, skillPlanContribution]{
		ID: "skills", SchemaVersion: 1, Empty: func() []skills.SkillReference { return []skills.SkillReference{} },
		Resolve: func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
			catalog, err := discoverSkills(ctx)
			if err != nil {
				return nil, err
			}
			return skills.ResolveReferences(references, catalog)
		},
		Contribute: func(selected []skills.SkillBundle) (skillPlanContribution, error) {
			return skillPlanContribution{selected: selected}, nil
		},
		Count: func(selection []skills.SkillReference) int { return len(selection) },
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := &launchCalls{}
	switchBinding, err := category.Bind(category.Definition[switchSelection, switchResolved, switchContribution]{
		ID: "switches", SchemaVersion: 1, Empty: func() switchSelection { return switchSelection{Codes: []int{}} },
		Resolve: func(ctx context.Context, selection switchSelection) (switchResolved, error) {
			catalog, err := discoverSwitches(ctx)
			if err != nil {
				return switchResolved{}, err
			}
			labels := make([]string, 0, len(selection.Codes))
			for _, code := range selection.Codes {
				for _, option := range catalog.Options {
					if option.Code == code {
						labels = append(labels, option.Label)
					}
				}
			}
			return switchResolved{Labels: labels}, nil
		},
		Contribute: func(resolved switchResolved) (switchContribution, error) {
			return switchContribution{resolved: resolved, calls: calls}, nil
		},
		Count: func(selection switchSelection) int { return len(selection.Codes) },
	})
	if err != nil {
		t.Fatal(err)
	}
	categories, err := category.NewRegistry("devin", skillsBinding.Registration(), switchBinding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	skillsEditorRegistration, err := RegisterSkillsEditor(skillsBinding, discoverSkills)
	if err != nil {
		t.Fatal(err)
	}
	switchEditorRegistration, err := RegisterEditor(EditorDefinition[switchDiscovery, switchEditor]{
		ID: "switches", Category: switchBinding.Registration(),
		New:      func(draft category.Draft) switchEditor { return switchEditor{draft: draft, binding: switchBinding} },
		Discover: discoverSwitches,
		Loaded: func(editor switchEditor, discovery switchDiscovery) (switchEditor, error) {
			editor.options = append([]switchOption(nil), discovery.Options...)
			return editor, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	editors, err := NewEditorRegistry(categories, skillsEditorRegistration, switchEditorRegistration)
	if err != nil {
		t.Fatal(err)
	}
	return multiCategoryFixture{categories: categories, editors: editors, skillsBinding: skillsBinding, switchBinding: switchBinding, calls: calls}
}

func TestUnrelatedCategoryCompletesBuilderStoreResolutionAndContributionLifecycle(t *testing.T) {
	bundle := skills.SkillBundle{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "review"}, DisplayName: "review", BundlePath: "/review"}
	switches := switchDiscovery{Options: []switchOption{{Code: 10, Label: "alpha"}, {Code: 20, Label: "beta"}}}
	fixture := newMultiCategoryFixture(t,
		func(context.Context) ([]skills.SkillBundle, error) { return []skills.SkillBundle{bundle}, nil },
		func(context.Context) (switchDiscovery, error) { return switches, nil },
	)
	store := profile.NewStore(t.TempDir(), fixture.categories)
	model, err := NewModel("multi", fixture.categories.NewDraft(), fixture.editors)
	if err != nil {
		t.Fatal(err)
	}
	model = model.WithSaver(func(ctx context.Context, draft category.Draft) (string, error) {
		candidate, err := fixture.categories.NewProfile("multi", draft)
		if err != nil {
			return "", err
		}
		return store.CreateContext(ctx, candidate)
	})

	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if command == nil || model.editors[0].loadState != loading || model.editors[1].loadState != unloaded {
		t.Fatalf("opening Skills did not load it independently: %#v", model.editors)
	}
	model, _ = updateCommand(t, model, command())
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model, _ = updateCommand(t, model, command())
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'q', Text: "q"}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))

	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if view := model.View().Content; !strings.Contains(view, "query=q cursor=1 scroll=1 selected=20") {
		t.Fatalf("unrelated editor state was not retained:\n%s", view)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if command == nil || model.screen != savingScreen {
		t.Fatal("multi-category draft did not start saving")
	}
	model, quit := updateCommand(t, model, command())
	if quit == nil || !model.Outcome().Create {
		t.Fatalf("save outcome = %#v", model.Outcome())
	}

	saved, err := store.Load("multi")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := fixture.categories.Resolve(context.Background(), saved)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := resolved.Plan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sections) != 2 || plan.Sections[0].Items[0].Label != "review" || plan.Sections[1].Items[0].Label != "beta" {
		t.Fatalf("ordered contributions = %#v", plan.Sections)
	}
	if err := resolved.Materialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := resolved.Verify(context.Background(), launch.VerificationContext{}); err != nil {
		t.Fatal(err)
	}
	if *fixture.calls != (launchCalls{materialized: 1, verified: 1}) {
		t.Fatalf("switch contribution calls = %#v", fixture.calls)
	}
}

func TestMultipleCategoriesRecoverDiscoveryIndependently(t *testing.T) {
	for _, target := range []int{0, 1} {
		t.Run([]string{"skills", "switches"}[target], func(t *testing.T) {
			calls := [2]int{}
			fixture := newMultiCategoryFixture(t,
				func(context.Context) ([]skills.SkillBundle, error) {
					calls[0]++
					if calls[0] < 3 {
						return nil, errors.New("skills unavailable")
					}
					return []skills.SkillBundle{}, nil
				},
				func(context.Context) (switchDiscovery, error) {
					calls[1]++
					if calls[1] < 3 {
						return switchDiscovery{}, errors.New("switches unavailable")
					}
					return switchDiscovery{}, nil
				},
			)
			model, err := NewModel("recovery", fixture.categories.NewDraft(), fixture.editors)
			if err != nil {
				t.Fatal(err)
			}
			if target == 1 {
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
			}
			model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
			if command == nil || model.editors[target].loadState != loading || model.editors[1-target].loadState != unloaded {
				t.Fatal("category did not start independently")
			}
			model, _ = updateCommand(t, model, command())
			if model.screen != loadFailureScreen {
				t.Fatal("failed discovery did not show failure")
			}
			model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
			model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
			model, _ = updateCommand(t, model, command())
			model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'r', Text: "r"}))
			model, _ = updateCommand(t, model, command())
			if model.screen != categoryScreen || model.editors[target].loadState != loaded || model.editors[1-target].loadState != unloaded || calls[target] != 3 {
				t.Fatalf("independent retry state = screen %v, calls %#v, slots %#v", model.screen, calls, model.editors)
			}
		})
	}
}

func TestFailedLoadConfirmationNamesEveryCategoryBeforeEmptyConfirmation(t *testing.T) {
	fixture := newMultiCategoryFixture(t,
		func(context.Context) ([]skills.SkillBundle, error) { return nil, errors.New("skills offline") },
		func(context.Context) (switchDiscovery, error) {
			return switchDiscovery{}, errors.New("switches offline")
		},
	)
	store := profile.NewStore(t.TempDir(), fixture.categories)
	model, err := NewModel("failed", fixture.categories.NewDraft(), fixture.editors)
	if err != nil {
		t.Fatal(err)
	}
	model = model.WithSaver(func(ctx context.Context, draft category.Draft) (string, error) {
		candidate, err := fixture.categories.NewProfile("failed", draft)
		if err != nil {
			return "", err
		}
		return store.CreateContext(ctx, candidate)
	})
	model, command := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model, _ = updateCommand(t, model, command())
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model, _ = updateCommand(t, model, command())
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if view := model.View().Content; !strings.Contains(view, "Skills, Switches") {
		t.Fatalf("failed-load confirmation does not name every category:\n%s", view)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if view := model.View().Content; !strings.Contains(view, "Create an empty Profile") || model.Outcome().Create {
		t.Fatalf("failed-load confirmation did not remain separate from empty confirmation:\n%s", view)
	}
	model, command = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if command == nil || model.screen != savingScreen {
		t.Fatal("confirmed empty multi-category Profile did not start saving")
	}
	model, quit := updateCommand(t, model, command())
	if quit == nil || !model.Outcome().Create {
		t.Fatal("confirmed empty multi-category Profile did not finish saving")
	}
	saved, err := store.Load("failed")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(saved.Categories["skills"].Selection); got != "[]" {
		t.Fatalf("saved empty Skills selection = %s", got)
	}
	if got := string(saved.Categories["switches"].Selection); got != `{"codes":[]}` {
		t.Fatalf("saved empty Switches selection = %s", got)
	}
}

func TestChangedMultiCategoryDraftCancellationRetainsBothEditors(t *testing.T) {
	fixture := newMultiCategoryFixture(t,
		func(context.Context) ([]skills.SkillBundle, error) { return []skills.SkillBundle{}, nil },
		func(context.Context) (switchDiscovery, error) {
			return switchDiscovery{Options: []switchOption{{Code: 10, Label: "alpha"}}}, nil
		},
	)
	draft := fixture.categories.NewDraft()
	if err := category.SetSelection(&draft, fixture.skillsBinding, []skills.SkillReference{{Source: "devin-config", RelativePath: "remember"}}); err != nil {
		t.Fatal(err)
	}
	model, err := NewModel("cancel", fixture.categories.NewDraft(), fixture.editors)
	if err != nil {
		t.Fatal(err)
	}
	model.draft = draft
	model.editors[0].editor = model.editors[0].editor.WithDraft(draft)
	model.editors[1].editor = model.editors[1].editor.WithDraft(draft)
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if model.screen != discardScreen {
		t.Fatal("changed multi-category Draft skipped discard confirmation")
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if model.screen != overviewScreen {
		t.Fatal("declining discard did not restore overview")
	}
	model, _ = updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	model, quit := updateCommand(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if quit == nil || !model.Outcome().Cancelled {
		t.Fatal("confirmed multi-category cancellation did not quit")
	}
	selected, err := category.Selection(model.Outcome().Draft, fixture.skillsBinding)
	if err != nil || !reflect.DeepEqual(selected, []skills.SkillReference{{Source: "devin-config", RelativePath: "remember"}}) {
		t.Fatalf("cancelled Draft lost retained selection: %#v, %v", selected, err)
	}
}

func TestRuntimeRendersMultipleCategoriesAndRestoresAlternateScreen(t *testing.T) {
	fixture := newMultiCategoryFixture(t,
		func(context.Context) ([]skills.SkillBundle, error) { return nil, nil },
		func(context.Context) (switchDiscovery, error) { return switchDiscovery{}, nil },
	)
	model, err := NewModel("runtime-multi", fixture.categories.NewDraft(), fixture.editors)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	input, writer := io.Pipe()
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = writer.Write([]byte("\x03"))
		_ = writer.Close()
	}()
	program := tea.NewProgram(model, tea.WithInput(input), tea.WithOutput(&output), tea.WithWindowSize(80, 24), tea.WithEnvironment([]string{"TERM=xterm-256color", "NO_COLOR=1"}))
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
	if !strings.Contains(normalized, "Skills") || !strings.Contains(normalized, "Switches") {
		t.Fatalf("multi-category runtime output = %q", normalized)
	}
}

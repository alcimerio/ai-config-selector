package builder

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type registrySelection string
type registryResolved int
type registryDiscovery struct{ Items []int }

type registryContribution struct{}

func (registryContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (registryContribution) Materialize(string) error                         { return nil }
func (registryContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

type registryEditor struct{ draft category.Draft }

func (editor registryEditor) Init() tea.Cmd                       { return nil }
func (editor registryEditor) Update(tea.Msg) (tea.Model, tea.Cmd) { return editor, nil }
func (editor registryEditor) View() tea.View                      { return tea.NewView("Registry") }
func (editor registryEditor) Draft() category.Draft               { return editor.draft }
func (registryEditor) ListFocused() bool                          { return true }

func TestEditorRegistryRejectsInvalidAssemblyBeforeTheBuilderRuns(t *testing.T) {
	binding := mustRegistryBinding(t, "notes")
	categories, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	valid := mustEditorRegistration(t, EditorDefinition[registryDiscovery]{
		ID:       "notes",
		Category: binding.Registration(),
		New:      func(draft category.Draft) Editor { return registryEditor{draft: draft} },
		Discover: func(context.Context) (registryDiscovery, error) { return registryDiscovery{}, nil },
		Loaded:   func(editor Editor, _ registryDiscovery) (Editor, error) { return editor, nil },
	})

	for name, registrations := range map[string][]EditorRegistration{
		"missing":   nil,
		"duplicate": {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewEditorRegistry(categories, registrations...); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("assembly error = %v, want %s", err, name)
			}
		})
	}

	otherBinding := mustRegistryBinding(t, "notes")
	incompatible := mustEditorRegistration(t, EditorDefinition[registryDiscovery]{
		ID: "notes", Category: otherBinding.Registration(),
		New:      func(draft category.Draft) Editor { return registryEditor{draft: draft} },
		Discover: func(context.Context) (registryDiscovery, error) { return registryDiscovery{}, nil },
		Loaded:   func(editor Editor, _ registryDiscovery) (Editor, error) { return editor, nil },
	})
	if _, err := NewEditorRegistry(categories, incompatible); err == nil || !strings.Contains(err.Error(), "type-incompatible") {
		t.Fatalf("incompatible assembly error = %v", err)
	}

	if _, err := RegisterEditor(EditorDefinition[registryDiscovery]{
		ID: "other", Category: binding.Registration(),
		New:      func(draft category.Draft) Editor { return registryEditor{draft: draft} },
		Discover: func(context.Context) (registryDiscovery, error) { return registryDiscovery{}, nil },
		Loaded:   func(editor Editor, _ registryDiscovery) (Editor, error) { return editor, nil },
	}); err == nil || !strings.Contains(err.Error(), "mismatched") {
		t.Fatalf("mismatched registration error = %v", err)
	}
}

func mustRegistryBinding(t *testing.T, id string) category.Binding[registrySelection, registryResolved, registryContribution] {
	t.Helper()
	binding, err := category.Bind(category.Definition[registrySelection, registryResolved, registryContribution]{
		ID: id, SchemaVersion: 1,
		Empty:      func() registrySelection { return "" },
		Resolve:    func(context.Context, registrySelection) (registryResolved, error) { return 0, nil },
		Contribute: func(registryResolved) (registryContribution, error) { return registryContribution{}, nil },
		Count: func(selection registrySelection) int {
			if selection == "" {
				return 0
			}
			return 1
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func mustEditorRegistration[D any](t *testing.T, definition EditorDefinition[D]) EditorRegistration {
	t.Helper()
	registration, err := RegisterEditor(definition)
	if err != nil {
		t.Fatal(err)
	}
	return registration
}

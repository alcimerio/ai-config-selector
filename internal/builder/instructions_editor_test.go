package builder

import (
	"context"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
)

type instructionTestProjection struct{}

func (instructionTestProjection) ID() string   { return "test" }
func (instructionTestProjection) Version() int { return 1 }
func (instructionTestProjection) Expected(v []instructions.Bundle) ([]instructions.Bundle, error) {
	return v, nil
}
func (instructionTestProjection) Materialize(string, []instructions.Bundle) error { return nil }

func TestInstructionsEditorTogglesAndPreservesMissingSelection(t *testing.T) {
	binding, err := commonprofile.NewInstructionsBinding(func(context.Context, []instructions.Reference) ([]instructions.Bundle, error) { return nil, nil }, instructionTestProjection{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("test", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	missing := instructions.Reference{Source: instructions.SourceID, RelativePath: "missing.md"}
	selected := instructions.Reference{Source: instructions.SourceID, RelativePath: "selected.md"}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, []instructions.Reference{missing}); err != nil {
		t.Fatal(err)
	}
	editor := instructionEditor{draft: draft, binding: binding, catalog: []instructions.Bundle{{Reference: selected}}}
	model, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "}))
	editor = model.(instructionEditor)
	got, err := category.Selection(editor.Draft(), binding)
	if err != nil || len(got) != 2 || got[0] != missing || got[1] != selected {
		t.Fatalf("editor did not preserve missing ref and add selected ref: %#v, %v", got, err)
	}
}

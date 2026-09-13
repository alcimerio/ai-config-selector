package builder

import (
	"context"
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
)

func TestReviewCanNavigateToAndRemoveMissingInstruction(t *testing.T) {
	binding, err := commonprofile.NewInstructionsBinding(func(context.Context, []instructions.Reference) ([]instructions.Bundle, error) { return nil, nil }, instructionTestProjection{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("test", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	missing := instructions.Reference{Source: instructions.SourceID, RelativePath: "missing.md"}
	available := instructions.Reference{Source: instructions.SourceID, RelativePath: "available.md"}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, []instructions.Reference{missing}); err != nil {
		t.Fatal(err)
	}
	editor := instructionEditor{draft: draft, binding: binding, catalog: []instructions.Bundle{{Reference: available}}, discovered: true}
	if got := editor.Unresolved(); !reflect.DeepEqual(got, []string{"acs-instructions:missing.md (missing)"}) {
		t.Fatalf("missing selection warnings = %v", got)
	}
	next, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Text: "down"}))
	next, _ = next.(instructionEditor).Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "}))
	got, err := category.Selection(next.(instructionEditor).Draft(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("cannot remove missing instruction with Down+Space; selections=%#v", got)
	}
}

func TestInstructionDiscoveryFailureKeepsUnresolvedWarning(t *testing.T) {
	binding, err := commonprofile.NewInstructionsBinding(func(context.Context, []instructions.Reference) ([]instructions.Bundle, error) { return nil, nil }, instructionTestProjection{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("test", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	missing := instructions.Reference{Source: instructions.SourceID, RelativePath: "missing.md"}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, []instructions.Reference{missing}); err != nil {
		t.Fatal(err)
	}
	editor := instructionEditor{draft: draft, binding: binding}.DiscoveryFailed().(instructionEditor)
	if got := editor.Unresolved(); !reflect.DeepEqual(got, []string{"acs-instructions:missing.md (unavailable/unchecked)"}) {
		t.Fatalf("discovery failure warnings = %v", got)
	}
}

package builder

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
)

func TestEnvironmentEditorAddsEditsRemovesAndCancels(t *testing.T) {
	binding, err := commonprofile.NewEnvironmentBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	editor := environmentEditor{draft: registry.NewDraft(), binding: binding}
	editor = environmentEditorPress(editor, "a")
	environmentEditorType(&editor, "mode")
	editor = environmentEditorPress(editor, "enter")
	environmentEditorType(&editor, "BUILD_MODE")
	editor = environmentEditorPress(editor, "enter")
	editor = environmentEditorPress(editor, "enter")
	environmentEditorType(&editor, "HOST_MODE")
	editor = environmentEditorPress(editor, "enter")
	editor = environmentEditorPress(editor, "space")
	editor = environmentEditorPress(editor, "enter")
	selection, err := category.Selection(editor.draft, binding)
	if err != nil || len(selection.Entries) != 1 || !selection.Entries[0].Required || selection.Entries[0].Source.Name != "HOST_MODE" {
		t.Fatalf("added selection = %#v, %v", selection, err)
	}

	original := selection
	editor = environmentEditorPress(editor, "e")
	editor.form.entry.Destination = "PATH"
	editor.form.field = 4
	editor = environmentEditorPress(editor, "enter")
	if editor.form == nil || editor.err == "" {
		t.Fatal("reserved invalid edit was accepted")
	}
	editor = environmentEditorPress(editor, "esc")
	selection, _ = category.Selection(editor.draft, binding)
	if !reflect.DeepEqual(selection, original) {
		t.Fatalf("cancelled invalid edit changed draft: got %#v want %#v", selection, original)
	}

	editor = environmentEditorPress(editor, "e")
	editor.form.field = 2
	editor = environmentEditorPress(editor, "space")
	editor.form.entry.Source.Reference = "HOST_TOKEN"
	editor.form.field = 4
	editor = environmentEditorPress(editor, "enter")
	selection, _ = category.Selection(editor.draft, binding)
	if selection.Entries[0].Classification != environmentintent.ClassificationSecret || selection.Entries[0].Source.Reference != "HOST_TOKEN" || !selection.Entries[0].Required {
		t.Fatalf("secret edit = %#v", selection)
	}
	view := editor.View().Content
	if strings.Contains(view, "HOST_TOKEN") || !strings.Contains(view, "<redacted-reference>") {
		t.Fatalf("list leaked secret reference: %q", view)
	}
	editor = environmentEditorPress(editor, "d")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 0 {
		t.Fatalf("delete failed: %#v", selection)
	}
}

func environmentEditorPress(editor environmentEditor, value string) environmentEditor {
	code := rune(0)
	switch value {
	case "enter":
		code = tea.KeyEnter
	case "space":
		code = tea.KeySpace
	case "esc":
		code = tea.KeyEsc
	default:
		code = []rune(value)[0]
	}
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: code, Text: value}))
	return updated.(environmentEditor)
}

func environmentEditorType(editor *environmentEditor, value string) {
	for _, character := range value {
		updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: character, Text: string(character)}))
		*editor = updated.(environmentEditor)
	}
}

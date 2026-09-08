package builder

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPathsEditorAddsEditsRemovesAndCancels(t *testing.T) {
	binding, err := commonprofile.NewPathsBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	editor := pathsEditor{draft: registry.NewDraft(), binding: binding}

	editor = pathEditorPress(editor, "a")
	for _, character := range "cache" {
		editor = pathEditorText(editor, character)
	}
	for i := 0; i < 4; i++ {
		editor = pathEditorPress(editor, "enter")
	}
	for _, character := range "tmp/cache" {
		editor = pathEditorText(editor, character)
	}
	editor = pathEditorPress(editor, "enter")
	selection, err := category.Selection(editor.draft, binding)
	if err != nil || len(selection.Entries) != 1 || selection.Entries[0].ID != "cache" || selection.Entries[0].Reference.Path != "tmp/cache" {
		t.Fatalf("added selection = %#v, %v", selection, err)
	}

	editor = pathEditorPress(editor, "e")
	editor = pathEditorPress(editor, "down")
	editor = pathEditorPress(editor, "space")
	for i := 0; i < 3; i++ {
		editor = pathEditorPress(editor, "down")
	}
	editor = pathEditorPress(editor, "enter")
	selection, _ = category.Selection(editor.draft, binding)
	if selection.Entries[0].Access != launch.PathAccessReadWrite {
		t.Fatalf("edit was not saved: %#v", selection)
	}

	editor = pathEditorPress(editor, "a")
	editor = pathEditorText(editor, 'x')
	editor = pathEditorPress(editor, "esc")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 1 {
		t.Fatalf("cancel changed selection: %#v", selection)
	}

	editor = pathEditorPress(editor, "d")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 0 {
		t.Fatalf("delete failed: %#v", selection)
	}
}

func pathEditorPress(editor pathsEditor, value string) pathsEditor {
	code := rune(0)
	switch value {
	case "enter":
		code = tea.KeyEnter
	case "down":
		code = tea.KeyDown
	case "space":
		code = tea.KeySpace
	case "esc":
		code = tea.KeyEsc
	default:
		code = []rune(value)[0]
	}
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: code, Text: value}))
	return updated.(pathsEditor)
}

func pathEditorText(editor pathsEditor, value rune) pathsEditor {
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: value, Text: string(value)}))
	return updated.(pathsEditor)
}

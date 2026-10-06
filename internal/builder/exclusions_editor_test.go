package builder

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
)

func TestExclusionsEditorAddsEditsRemovesAndCancels(t *testing.T) {
	binding, err := commonprofile.NewExclusionsBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	editor := exclusionsEditor{draft: registry.NewDraft(), binding: binding}

	editor = exclusionEditorPress(editor, "a")
	for _, character := range "cache" {
		editor = exclusionEditorText(editor, character)
	}
	for i := 0; i < 3; i++ {
		editor = exclusionEditorPress(editor, "enter")
	}
	for _, character := range "tmp/cache" {
		editor = exclusionEditorText(editor, character)
	}
	editor = exclusionEditorPress(editor, "enter")
	selection, err := category.Selection(editor.draft, binding)
	if err != nil || len(selection.Entries) != 1 || selection.Entries[0].ID != "cache" || selection.Entries[0].Reference.Path != "tmp/cache" {
		t.Fatalf("added selection = %#v, %v", selection, err)
	}

	editor = exclusionEditorPress(editor, "e")
	editor = exclusionEditorPress(editor, "down")
	editor = exclusionEditorPress(editor, "space")
	for i := 0; i < 2; i++ {
		editor = exclusionEditorPress(editor, "down")
	}
	editor = exclusionEditorPress(editor, "enter")
	selection, _ = category.Selection(editor.draft, binding)
	if selection.Entries[0].Type != "directory" {
		t.Fatalf("edit was not saved: %#v", selection)
	}

	editor = exclusionEditorPress(editor, "a")
	editor = exclusionEditorText(editor, 'x')
	editor = exclusionEditorPress(editor, "esc")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 1 {
		t.Fatalf("cancel changed selection: %#v", selection)
	}

	editor = exclusionEditorPress(editor, "d")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 0 {
		t.Fatalf("delete failed: %#v", selection)
	}
}

func exclusionEditorPress(editor exclusionsEditor, value string) exclusionsEditor {
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
	return updated.(exclusionsEditor)
}

func exclusionEditorText(editor exclusionsEditor, value rune) exclusionsEditor {
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: value, Text: string(value)}))
	return updated.(exclusionsEditor)
}

package builder

import (
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestExecutablesEditorAddsEditsRemovesAndCancels(t *testing.T) {
	binding, err := commonprofile.NewExecutablesBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	editor := executablesEditor{draft: registry.NewDraft(), binding: binding}

	editor = executableEditorPress(editor, "a")
	for _, value := range "repo-tool" {
		editor = executableEditorText(editor, value)
	}
	editor = executableEditorPress(editor, "enter")
	editor = executableEditorPress(editor, "space")
	editor = executableEditorPress(editor, "enter")
	for _, value := range "bin/my tool" {
		editor = executableEditorText(editor, value)
	}
	editor = executableEditorPress(editor, "enter")
	selection, err := category.Selection(editor.draft, binding)
	if err != nil || len(selection.Entries) != 1 || selection.Entries[0].Reference.Path != "bin/my tool" || selection.Entries[0].Reference.Kind != string(launch.ExecutableReferenceWorkspaceRelative) {
		t.Fatalf("added selection = %#v, %v", selection, err)
	}

	original := selection
	editor = executableEditorPress(editor, "e")
	editor.form.entry.ID = "INVALID"
	editor.form.field = 2
	editor = executableEditorPress(editor, "enter")
	if editor.form == nil || editor.err == "" {
		t.Fatal("invalid edit did not remain in form")
	}
	editor = executableEditorPress(editor, "esc")
	selection, _ = category.Selection(editor.draft, binding)
	if !reflect.DeepEqual(selection, original) {
		t.Fatalf("cancelled invalid edit changed draft: got %#v want %#v", selection, original)
	}

	editor = executableEditorPress(editor, "e")
	editor.form.entry.ID = "renamed-tool"
	editor.form.field = 2
	editor = executableEditorPress(editor, "enter")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 1 || selection.Entries[0].ID != "renamed-tool" {
		t.Fatalf("edit was not saved: %#v", selection)
	}
	editor = executableEditorPress(editor, "d")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.Entries) != 0 {
		t.Fatalf("delete failed: %#v", selection)
	}
}

func executableEditorPress(editor executablesEditor, value string) executablesEditor {
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
	return updated.(executablesEditor)
}

func executableEditorText(editor executablesEditor, value rune) executablesEditor {
	if value == ' ' {
		return executableEditorPress(editor, "space")
	}
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: value, Text: string(value)}))
	return updated.(executablesEditor)
}

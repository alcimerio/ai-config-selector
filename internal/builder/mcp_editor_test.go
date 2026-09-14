package builder

import (
	"encoding/json"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
)

func TestMCPEditorStartsInListAndAddsEditsSavesAndReopens(t *testing.T) {
	binding, err := commonprofile.NewMCPBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	registration, err := RegisterMCPEditor(binding)
	if err != nil {
		t.Fatal(err)
	}
	editor := registration.new(registry.NewDraft()).(mcpEditor)
	if editor.editing != -1 {
		t.Fatal("new editor did not start in list mode")
	}
	editor = mcpEditorPress(editor, "a")
	editor = mcpEditorText(editor, `{"id":"demo","transport":"stdio","executableRef":"server-bin","arguments":[],"inputRefs":[],"environmentRefs":[]}`)
	editor = mcpEditorPress(editor, "enter")
	selection, err := category.Selection(editor.draft, binding)
	if err != nil || len(selection.Servers) != 1 || selection.Servers[0].ID != "demo" || selection.Servers[0].Arguments == nil {
		t.Fatalf("added MCP selection = %#v, %v", selection, err)
	}
	editor = mcpEditorPress(editor, "enter")
	if editor.editing != 0 {
		t.Fatal("existing row did not open for editing")
	}
	editor.input = `{"id":"demo2","transport":"stdio","executableRef":"server-bin","arguments":[],"inputRefs":[],"environmentRefs":[]}`
	editor = mcpEditorPress(editor, "enter")
	selection, err = category.Selection(editor.draft, binding)
	if err != nil || len(selection.Servers) != 1 || selection.Servers[0].ID != "demo2" {
		t.Fatalf("edited MCP selection = %#v, %v", selection, err)
	}
	reopened := registration.new(editor.draft).(mcpEditor)
	if reopened.editing != -1 {
		t.Fatal("reopened editor did not start in list mode")
	}
	reopenedSelection, err := category.Selection(reopened.draft, binding)
	if err != nil || len(reopenedSelection.Servers) != 1 || reopenedSelection.Servers[0].ID != "demo2" {
		t.Fatalf("reopened MCP selection = %#v, %v", reopenedSelection, err)
	}
	encoded, err := commonprofile.EncodeMCPSelection(reopenedSelection)
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("saved MCP encoding = %s, %v", encoded, err)
	}
}

func mcpEditorPress(editor mcpEditor, value string) mcpEditor {
	code := rune(value[0])
	switch value {
	case "enter":
		code = tea.KeyEnter
	case "esc":
		code = tea.KeyEsc
	case "backspace":
		code = tea.KeyBackspace
	}
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: code, Text: value}))
	return updated.(mcpEditor)
}

func mcpEditorText(editor mcpEditor, value string) mcpEditor {
	updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: rune(value[0]), Text: value}))
	return updated.(mcpEditor)
}

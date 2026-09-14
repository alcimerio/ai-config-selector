package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/mcpintent"
)

// RegisterMCPEditor accepts one strict typed server descriptor at a time. The
// JSON form contains only references; arbitrary argv literals are rejected by
// the schema before a draft can be saved.
func RegisterMCPEditor(binding commonprofile.MCPBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, mcpEditor]{
		ID: commonprofile.MCPCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) mcpEditor { return mcpEditor{draft: draft, binding: binding, editing: -1} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor mcpEditor, _ struct{}) (mcpEditor, error) { return editor, nil },
	})
}

type mcpEditor struct {
	draft   category.Draft
	binding commonprofile.MCPBinding
	cursor  int
	editing int
	input   string
	err     string
}

func (editor mcpEditor) Init() tea.Cmd { return nil }
func (editor mcpEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return editor, nil
	}
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.editing >= 0 {
		switch press.String() {
		case "esc":
			editor.editing, editor.input, editor.err = -1, "", ""
		case "backspace":
			editor.input = trimLastRune(editor.input)
		case "enter":
			var entry mcpintent.Server
			wrapped := []byte(`{"servers":[` + editor.input + `]}`)
			parsed, err := mcpintent.Decode(wrapped)
			if err == nil && len(parsed.Servers) == 1 {
				entry = parsed.Servers[0]
			} else if err == nil {
				err = fmt.Errorf("enter exactly one MCP server object")
			}
			if err != nil {
				editor.err = err.Error()
				return editor, nil
			}
			selection.Servers = append([]mcpintent.Server(nil), selection.Servers...)
			if editor.editing == len(selection.Servers) {
				selection.Servers = append(selection.Servers, entry)
			} else {
				selection.Servers[editor.editing] = entry
			}
			if err := category.SetSelection(&editor.draft, editor.binding, selection); err != nil {
				editor.err = err.Error()
				return editor, nil
			}
			editor.editing, editor.input, editor.err = -1, "", ""
		default:
			value := press.Key().Text
			if value != "" && !strings.ContainsFunc(value, unicode.IsControl) {
				editor.input += value
			}
		}
		return editor, nil
	}
	switch press.String() {
	case "up":
		if editor.cursor > 0 {
			editor.cursor--
		}
	case "down":
		if editor.cursor < len(selection.Servers) {
			editor.cursor++
		}
	case "a":
		editor.editing, editor.input, editor.err = len(selection.Servers), "", ""
	case "e", "enter":
		if editor.cursor < len(selection.Servers) {
			encoded, _ := json.Marshal(selection.Servers[editor.cursor])
			editor.editing, editor.input, editor.err = editor.cursor, string(encoded), ""
		}
	case "d", "backspace", "delete":
		if editor.cursor < len(selection.Servers) {
			selection.Servers = append(selection.Servers[:editor.cursor:editor.cursor], selection.Servers[editor.cursor+1:]...)
			_ = category.SetSelection(&editor.draft, editor.binding, selection)
			if editor.cursor > len(selection.Servers) {
				editor.cursor = len(selection.Servers)
			}
		}
	}
	return editor, nil
}

func (editor mcpEditor) Draft() category.Draft                 { return editor.draft }
func (editor mcpEditor) WithDraft(draft category.Draft) Editor { editor.draft = draft; return editor }
func (editor mcpEditor) ListFocused() bool                     { return editor.editing < 0 }
func (editor mcpEditor) View() tea.View {
	if editor.editing >= 0 {
		var out strings.Builder
		out.WriteString("Paste one local stdio MCP server JSON object (reference fields only):\n\n")
		out.WriteString(editor.input)
		if editor.err != "" {
			fmt.Fprintf(&out, "\n\nInvalid server: %s", editor.err)
		}
		out.WriteString("\n\nEnter saves; Esc cancels. String argv values are not accepted; use path/environment references.")
		return tea.NewView(out.String())
	}
	selection, _ := category.Selection(editor.draft, editor.binding)
	var out strings.Builder
	out.WriteString("MCP servers (local stdio only)\n\n")
	if len(selection.Servers) == 0 {
		out.WriteString("No MCP servers selected.\n")
	}
	for index, server := range selection.Servers {
		marker := "  "
		if index == editor.cursor {
			marker = "> "
		}
		fmt.Fprintf(&out, "%s%s  executable:%s  argv refs:%d  inputs:%s  env:%s\n", marker, server.ID, server.ExecutableRef, len(server.Arguments), strings.Join(server.InputRefs, ","), strings.Join(server.EnvironmentRefs, ","))
	}
	if editor.cursor == len(selection.Servers) {
		out.WriteString("> Add server\n")
	} else {
		out.WriteString("  Add server\n")
	}
	out.WriteString("\nA add  E/Enter edit  D delete. Values and remote transports are not stored.")
	return tea.NewView(out.String())
}

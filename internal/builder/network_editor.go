package builder

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/networkintent"
)

func RegisterNetworkEditor(binding commonprofile.NetworkBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, networkEditor]{
		ID: commonprofile.NetworkCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) networkEditor { return networkEditor{draft: draft, binding: binding} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor networkEditor, _ struct{}) (networkEditor, error) { return editor, nil },
	})
}

type networkEditor struct {
	draft   category.Draft
	binding commonprofile.NetworkBinding
	cursor  int
	form    *string
	err     string
}

func (networkEditor) Init() tea.Cmd { return nil }
func (editor networkEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return editor, nil
	}
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.form != nil {
		value := *editor.form
		switch press.String() {
		case "esc":
			editor.form, editor.err = nil, ""
		case "backspace":
			if len(value) > 0 {
				value = value[:len(value)-1]
			}
			editor.form = &value
		case "enter":
			port, err := strconv.Atoi(value)
			if err == nil {
				selection.LoopbackPorts = append(append([]int(nil), selection.LoopbackPorts...), port)
				selection, err = networkintent.Canonical(selection)
				if err == nil {
					err = category.SetSelection(&editor.draft, editor.binding, selection)
				}
			}
			if err != nil {
				editor.err = "Enter one unique integer port from 1 to 65535 (at most 64 ports)."
			} else {
				editor.form, editor.err = nil, ""
			}
		default:
			if len(value) < 5 && len(press.Text) == 1 && press.Text[0] >= '0' && press.Text[0] <= '9' {
				value += press.Text
				editor.form = &value
			}
		}
		return editor, nil
	}
	switch press.String() {
	case "a":
		value := ""
		editor.form, editor.err = &value, ""
	case "up":
		if editor.cursor > 0 {
			editor.cursor--
		}
	case "down":
		if editor.cursor+1 < len(selection.LoopbackPorts) {
			editor.cursor++
		}
	case "d", "delete", "backspace":
		if len(selection.LoopbackPorts) > 0 {
			ports := append([]int(nil), selection.LoopbackPorts...)
			selection.LoopbackPorts = append(ports[:editor.cursor], ports[editor.cursor+1:]...)
			_ = category.SetSelection(&editor.draft, editor.binding, selection)
			if editor.cursor >= len(selection.LoopbackPorts) && editor.cursor > 0 {
				editor.cursor--
			}
		}
	}
	return editor, nil
}
func (editor networkEditor) View() tea.View {
	var out strings.Builder
	out.WriteString("Loopback network (macOS)\n\nOutbound loopback is denied except for these ports:\n")
	selection, _ := category.Selection(editor.draft, editor.binding)
	if len(selection.LoopbackPorts) == 0 {
		out.WriteString("  denied (default)\n")
	}
	for i, port := range selection.LoopbackPorts {
		cursor := " "
		if i == editor.cursor {
			cursor = ">"
		}
		fmt.Fprintf(&out, "%s %d\n", cursor, port)
	}
	if editor.form != nil {
		fmt.Fprintf(&out, "\nPort: %s\nEnter adds; Esc cancels.\n%s", *editor.form, editor.err)
	} else {
		out.WriteString("\na adds; d removes; arrows select.")
	}
	return tea.NewView(out.String())
}
func (editor networkEditor) Draft() category.Draft { return editor.draft }
func (editor networkEditor) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	selection, _ := category.Selection(draft, editor.binding)
	if editor.cursor >= len(selection.LoopbackPorts) {
		editor.cursor = max(0, len(selection.LoopbackPorts)-1)
	}
	editor.form, editor.err = nil, ""
	return editor
}
func (editor networkEditor) ListFocused() bool { return editor.form == nil }

package builder

import (
	"context"
	"fmt"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// RegisterWorkspaceEditor exposes only the two common workspace modes ACS can
// currently compile. It performs no discovery or host access.
func RegisterWorkspaceEditor[C launch.Contribution](binding category.Binding[launch.WorkspaceAccess, launch.WorkspaceAccess, C]) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, workspaceEditor[C]]{
		ID: "workspace", Category: binding.Registration(),
		New: func(draft category.Draft) workspaceEditor[C] {
			return workspaceEditor[C]{draft: draft, binding: binding}
		},
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor workspaceEditor[C], _ struct{}) (workspaceEditor[C], error) { return editor, nil },
	})
}

type workspaceEditor[C launch.Contribution] struct {
	draft   category.Draft
	binding category.Binding[launch.WorkspaceAccess, launch.WorkspaceAccess, C]
}

func (editor workspaceEditor[C]) Init() tea.Cmd { return nil }
func (editor workspaceEditor[C]) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return editor, nil
	}
	access, _ := category.Selection(editor.draft, editor.binding)
	switch press.String() {
	case "up", "down", "space", "enter":
		if access == launch.WorkspaceAccessReadWrite {
			access = launch.WorkspaceAccessReadOnly
		} else {
			access = launch.WorkspaceAccessReadWrite
		}
		_ = category.SetSelection(&editor.draft, editor.binding, access)
	}
	return editor, nil
}
func (editor workspaceEditor[C]) View() tea.View {
	access, _ := category.Selection(editor.draft, editor.binding)
	readOnly, readWrite := "[ ]", "[ ]"
	if access == launch.WorkspaceAccessReadWrite {
		readWrite = "[x]"
	} else {
		readOnly = "[x]"
	}
	return tea.NewView(fmt.Sprintf("Workspace access\n\n%s Read-only (default)\n%s Read and write (coding work)\n\nSpace/Enter toggles the explicit common grant.", readOnly, readWrite))
}
func (editor workspaceEditor[C]) Draft() category.Draft { return editor.draft }
func (editor workspaceEditor[C]) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	return editor
}
func (workspaceEditor[C]) ListFocused() bool { return true }

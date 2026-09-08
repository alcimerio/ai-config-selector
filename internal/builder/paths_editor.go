package builder

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// RegisterPathsEditor provides private explicit add/edit/remove authoring. It
// performs no discovery or host-path access.
func RegisterPathsEditor(binding commonprofile.PathsBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, pathsEditor]{
		ID: commonprofile.PathsCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) pathsEditor { return pathsEditor{draft: draft, binding: binding} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor pathsEditor, _ struct{}) (pathsEditor, error) { return editor, nil },
	})
}

type pathsEditor struct {
	draft   category.Draft
	binding commonprofile.PathsBinding
	cursor  int
	form    *pathEntryForm
	err     string
}

type pathEntryForm struct {
	editing int
	field   int
	entry   commonprofile.PathEntry
}

func (editor pathsEditor) Init() tea.Cmd { return nil }
func (editor pathsEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return editor, nil
	}
	if editor.form != nil {
		editor.updateForm(press)
		return editor, nil
	}
	selection, _ := category.Selection(editor.draft, editor.binding)
	switch press.String() {
	case "up":
		if editor.cursor > 0 {
			editor.cursor--
		}
	case "down":
		if editor.cursor+1 < len(selection.Entries) {
			editor.cursor++
		}
	case "a":
		editor.form = &pathEntryForm{editing: -1, entry: commonprofile.PathEntry{Access: launch.PathAccessReadOnly, Type: launch.PathTypeFile, Reference: commonprofile.PathReference{Kind: string(launch.PathReferenceWorkspaceRelative)}}}
		editor.err = ""
	case "e", "enter":
		if len(selection.Entries) != 0 {
			editor.form = &pathEntryForm{editing: editor.cursor, entry: selection.Entries[editor.cursor]}
			editor.err = ""
		}
	case "d", "backspace", "delete":
		if len(selection.Entries) != 0 {
			selection.Entries = append(selection.Entries[:editor.cursor:editor.cursor], selection.Entries[editor.cursor+1:]...)
			if category.SetSelection(&editor.draft, editor.binding, selection) == nil && editor.cursor >= len(selection.Entries) && editor.cursor > 0 {
				editor.cursor--
			}
		}
	}
	return editor, nil
}

func (editor *pathsEditor) updateForm(press tea.KeyPressMsg) {
	form := editor.form
	switch press.String() {
	case "esc":
		editor.form, editor.err = nil, ""
		return
	case "up":
		if form.field > 0 {
			form.field--
		}
		return
	case "down", "tab":
		if form.field < 4 {
			form.field++
		}
		return
	case "enter":
		if form.field < 4 {
			form.field++
			return
		}
		selection, _ := category.Selection(editor.draft, editor.binding)
		if form.editing < 0 {
			selection.Entries = append(selection.Entries, form.entry)
		} else {
			selection.Entries[form.editing] = form.entry
		}
		if err := category.SetSelection(&editor.draft, editor.binding, selection); err != nil {
			editor.err = err.Error()
			return
		}
		editor.form, editor.err = nil, ""
		return
	case "left", "right", "space":
		switch form.field {
		case 1:
			if form.entry.Access == launch.PathAccessReadOnly {
				form.entry.Access = launch.PathAccessReadWrite
			} else {
				form.entry.Access = launch.PathAccessReadOnly
			}
		case 2:
			if form.entry.Type == launch.PathTypeFile {
				form.entry.Type = launch.PathTypeDirectory
			} else {
				form.entry.Type = launch.PathTypeFile
			}
		case 3:
			if form.entry.Reference.Kind == string(launch.PathReferenceWorkspaceRelative) {
				form.entry.Reference.Kind = string(launch.PathReferenceLocalAbsolute)
			} else {
				form.entry.Reference.Kind = string(launch.PathReferenceWorkspaceRelative)
			}
		}
		return
	case "backspace":
		if form.field == 0 {
			form.entry.ID = trimLastRune(form.entry.ID)
		} else if form.field == 4 {
			form.entry.Reference.Path = trimLastRune(form.entry.Reference.Path)
		}
		return
	}
	text := press.Key().Text
	if text == "" || strings.ContainsFunc(text, unicode.IsControl) {
		return
	}
	if form.field == 0 {
		form.entry.ID += text
	} else if form.field == 4 {
		form.entry.Reference.Path += text
	}
}

func trimLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}

func (editor pathsEditor) Draft() category.Draft                 { return editor.draft }
func (editor pathsEditor) WithDraft(draft category.Draft) Editor { editor.draft = draft; return editor }
func (editor pathsEditor) ListFocused() bool                     { return editor.form == nil }
func (editor pathsEditor) View() tea.View {
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.form != nil {
		entry := editor.form.entry
		displayPath := entry.Reference.Path
		labels := []string{"ID", "Access", "Type", "Reference", "Path"}
		values := []string{entry.ID, string(entry.Access), string(entry.Type), entry.Reference.Kind, displayPath}
		var lines strings.Builder
		lines.WriteString("Filesystem path grant\n\n")
		for index := range labels {
			marker := "  "
			if index == editor.form.field {
				marker = "> "
			}
			fmt.Fprintf(&lines, "%s%s: %s\n", marker, labels[index], values[index])
		}
		if editor.err != "" {
			fmt.Fprintf(&lines, "\nInvalid entry: %s", editor.err)
		}
		lines.WriteString("\n\nEnter/Tab advances; arrows/Space toggle; Enter saves Path; Esc cancels.")
		return tea.NewView(lines.String())
	}
	var lines strings.Builder
	lines.WriteString("Additional filesystem paths\n\n")
	if len(selection.Entries) == 0 {
		lines.WriteString("No explicit grants.\n")
	}
	for index, entry := range selection.Entries {
		marker := "  "
		if index == editor.cursor {
			marker = "> "
		}
		displayPath := entry.Reference.Path
		if entry.Reference.Kind == string(launch.PathReferenceLocalAbsolute) {
			displayPath = filepath.Base(displayPath)
		}
		fmt.Fprintf(&lines, "%s%s  %s %s  %s:%s\n", marker, entry.ID, entry.Access, entry.Type, entry.Reference.Kind, displayPath)
	}
	lines.WriteString("\nA add  E/Enter edit  D delete. Local absolute values are basename-redacted in the list.")
	return tea.NewView(lines.String())
}

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

// RegisterExecutablesEditor provides explicit syntax-only authoring. It never
// searches for, opens, or hashes the entered executable reference.
func RegisterExecutablesEditor(binding commonprofile.ExecutablesBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, executablesEditor]{
		ID: commonprofile.ExecutablesCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) executablesEditor { return executablesEditor{draft: draft, binding: binding} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor executablesEditor, _ struct{}) (executablesEditor, error) { return editor, nil },
	})
}

type executablesEditor struct {
	draft   category.Draft
	binding commonprofile.ExecutablesBinding
	cursor  int
	form    *executableEntryForm
	err     string
}

type executableEntryForm struct {
	editing int
	field   int
	entry   commonprofile.ExecutableEntry
}

func (editor executablesEditor) Init() tea.Cmd { return nil }
func (editor executablesEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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
		editor.form = &executableEntryForm{editing: -1, entry: commonprofile.ExecutableEntry{Reference: commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceFixedSearchName)}}}
		editor.err = ""
	case "e", "enter":
		if len(selection.Entries) != 0 {
			editor.form = &executableEntryForm{editing: editor.cursor, entry: selection.Entries[editor.cursor]}
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

func (editor *executablesEditor) updateForm(press tea.KeyPressMsg) {
	form := editor.form
	switch press.String() {
	case "esc":
		editor.form, editor.err = nil, ""
	case "up":
		if form.field > 0 {
			form.field--
		}
	case "down", "tab":
		if form.field < 2 {
			form.field++
		}
	case "enter":
		if form.field < 2 {
			form.field++
			return
		}
		selection, _ := category.Selection(editor.draft, editor.binding)
		selection.Entries = append([]commonprofile.ExecutableEntry(nil), selection.Entries...)
		if form.editing < 0 {
			selection.Entries = append(selection.Entries, form.entry)
		} else {
			selection.Entries[form.editing] = form.entry
		}
		encoded, err := commonprofile.EncodeExecutableSelection(selection)
		if err != nil {
			editor.err = err.Error()
			return
		}
		selection, err = commonprofile.DecodeExecutableSelection(encoded)
		if err != nil {
			editor.err = err.Error()
			return
		}
		if err := category.SetSelection(&editor.draft, editor.binding, selection); err != nil {
			editor.err = err.Error()
			return
		}
		editor.form, editor.err = nil, ""
	case "left", "right":
		if form.field == 1 {
			switch form.entry.Reference.Kind {
			case string(launch.ExecutableReferenceFixedSearchName):
				form.entry.Reference.Kind = string(launch.ExecutableReferenceWorkspaceRelative)
			case string(launch.ExecutableReferenceWorkspaceRelative):
				form.entry.Reference.Kind = string(launch.ExecutableReferenceLocalAbsolute)
			default:
				form.entry.Reference.Kind = string(launch.ExecutableReferenceFixedSearchName)
			}
			form.entry.Reference.Name, form.entry.Reference.Path = "", ""
		}
	case "space":
		if form.field == 1 {
			switch form.entry.Reference.Kind {
			case string(launch.ExecutableReferenceFixedSearchName):
				form.entry.Reference.Kind = string(launch.ExecutableReferenceWorkspaceRelative)
			case string(launch.ExecutableReferenceWorkspaceRelative):
				form.entry.Reference.Kind = string(launch.ExecutableReferenceLocalAbsolute)
			default:
				form.entry.Reference.Kind = string(launch.ExecutableReferenceFixedSearchName)
			}
			form.entry.Reference.Name, form.entry.Reference.Path = "", ""
			return
		}
		if form.field == 2 && form.entry.Reference.Kind != string(launch.ExecutableReferenceFixedSearchName) {
			form.entry.Reference.Path += " "
		}
	case "backspace":
		if form.field == 0 {
			form.entry.ID = trimLastRune(form.entry.ID)
		} else if form.field == 2 {
			if form.entry.Reference.Kind == string(launch.ExecutableReferenceFixedSearchName) {
				form.entry.Reference.Name = trimLastRune(form.entry.Reference.Name)
			} else {
				form.entry.Reference.Path = trimLastRune(form.entry.Reference.Path)
			}
		}
	default:
		value := press.Key().Text
		if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
			return
		}
		if form.field == 0 {
			form.entry.ID += value
		} else if form.field == 2 {
			if form.entry.Reference.Kind == string(launch.ExecutableReferenceFixedSearchName) {
				form.entry.Reference.Name += value
			} else {
				form.entry.Reference.Path += value
			}
		}
	}
}

func (editor executablesEditor) Draft() category.Draft { return editor.draft }
func (editor executablesEditor) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	return editor
}
func (editor executablesEditor) ListFocused() bool { return editor.form == nil }
func (editor executablesEditor) View() tea.View {
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.form != nil {
		entry := editor.form.entry
		value := entry.Reference.Path
		if entry.Reference.Kind == string(launch.ExecutableReferenceFixedSearchName) {
			value = entry.Reference.Name
		}
		labels, values := []string{"ID", "Reference", "Name or path"}, []string{entry.ID, entry.Reference.Kind, value}
		var lines strings.Builder
		lines.WriteString("Executable visibility entry\n\n")
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
		lines.WriteString("\n\nEnter/Tab advances; arrows/Space change reference; Enter saves; Esc cancels.")
		return tea.NewView(lines.String())
	}
	var lines strings.Builder
	lines.WriteString("Additional visible executables\n\n")
	if len(selection.Entries) == 0 {
		lines.WriteString("No explicit executable visibility entries.\n")
	}
	for index, entry := range selection.Entries {
		marker := "  "
		if index == editor.cursor {
			marker = "> "
		}
		value := entry.Reference.Name
		if entry.Reference.Kind != string(launch.ExecutableReferenceFixedSearchName) {
			value = entry.Reference.Path
			if entry.Reference.Kind == string(launch.ExecutableReferenceLocalAbsolute) {
				value = filepath.Base(value)
			}
		}
		fmt.Fprintf(&lines, "%s%s  %s:%s\n", marker, entry.ID, entry.Reference.Kind, value)
	}
	lines.WriteString("\nA add  E/Enter edit  D delete. Entries add visibility only; local paths are basename-redacted here.")
	return tea.NewView(lines.String())
}

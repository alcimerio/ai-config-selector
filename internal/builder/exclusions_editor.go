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

// RegisterExclusionsEditor provides private explicit add/edit/remove authoring. It
// performs no discovery or host-path access.
func RegisterExclusionsEditor(binding commonprofile.ExclusionsBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, exclusionsEditor]{
		ID: commonprofile.ExclusionsCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) exclusionsEditor { return exclusionsEditor{draft: draft, binding: binding} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor exclusionsEditor, _ struct{}) (exclusionsEditor, error) { return editor, nil },
	})
}

type exclusionsEditor struct {
	draft   category.Draft
	binding commonprofile.ExclusionsBinding
	cursor  int
	form    *exclusionEntryForm
	err     string
}

type exclusionEntryForm struct {
	editing int
	field   int
	entry   commonprofile.ExclusionEntry
}

func (editor exclusionsEditor) Init() tea.Cmd { return nil }
func (editor exclusionsEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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
		editor.form = &exclusionEntryForm{editing: -1, entry: commonprofile.ExclusionEntry{Type: "file", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceWorkspaceRelative)}}}
		editor.err = ""
	case "e", "enter":
		if len(selection.Entries) != 0 {
			editor.form = &exclusionEntryForm{editing: editor.cursor, entry: selection.Entries[editor.cursor]}
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

func (editor *exclusionsEditor) updateForm(press tea.KeyPressMsg) {
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
		if form.field < 3 {
			form.field++
		}
		return
	case "enter":
		if form.field < 3 {
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
			if form.entry.Type == "file" {
				form.entry.Type = "directory"
			} else {
				form.entry.Type = "file"
			}
		case 2:
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
		} else if form.field == 3 {
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
	} else if form.field == 3 {
		form.entry.Reference.Path += text
	}
}

// Advisories reports non-blocking warnings for the mutation preview: nested
// entries and entries that differ only by letter case (APFS is
// case-insensitive). They never block saving.
func (editor exclusionsEditor) Advisories() []string {
	selection, err := category.Selection(editor.draft, editor.binding)
	if err != nil {
		return nil
	}
	return commonprofile.ExclusionWarnings(selection)
}

func (editor exclusionsEditor) Draft() category.Draft { return editor.draft }
func (editor exclusionsEditor) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	return editor
}
func (editor exclusionsEditor) ListFocused() bool { return editor.form == nil }
func (editor exclusionsEditor) View() tea.View {
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.form != nil {
		entry := editor.form.entry
		displayPath := entry.Reference.Path
		labels := []string{"ID", "Type", "Reference", "Path"}
		values := []string{entry.ID, string(entry.Type), entry.Reference.Kind, displayPath}
		var lines strings.Builder
		lines.WriteString("Excluded path\n\n")
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
	lines.WriteString("Excluded paths\n\n")
	if len(selection.Entries) == 0 {
		lines.WriteString("No excluded paths.\n")
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
		fmt.Fprintf(&lines, "%s%s  %s  %s:%s\n", marker, entry.ID, entry.Type, entry.Reference.Kind, displayPath)
	}
	if warnings := commonprofile.ExclusionWarnings(selection); len(warnings) != 0 {
		lines.WriteString("\nWarning: redundant entries (saved as entered; every entry is still enforced):\n")
		for _, warning := range warnings {
			fmt.Fprintf(&lines, "  ! %s\n", warning)
		}
	}
	lines.WriteString("\nBlock access to these files and folders in this Session.\nFolder names may remain visible. Git history and other copies are separate.\n\nA add  E/Enter edit  D delete. Local absolute values are basename-redacted in the list.")
	return tea.NewView(lines.String())
}

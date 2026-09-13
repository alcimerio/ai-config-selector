package builder

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
)

// RegisterEnvironmentEditor provides private syntax-only authoring. It never
// reads a selected host source or provider reference.
func RegisterEnvironmentEditor(binding commonprofile.EnvironmentBinding) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[struct{}, environmentEditor]{
		ID: commonprofile.EnvironmentCapabilityID, Category: binding.Registration(),
		New:      func(draft category.Draft) environmentEditor { return environmentEditor{draft: draft, binding: binding} },
		Discover: func(context.Context) (struct{}, error) { return struct{}{}, nil },
		Loaded:   func(editor environmentEditor, _ struct{}) (environmentEditor, error) { return editor, nil },
	})
}

type environmentEditor struct {
	draft   category.Draft
	binding commonprofile.EnvironmentBinding
	cursor  int
	form    *environmentEntryForm
	err     string
}

type environmentEntryForm struct {
	editing int
	field   int
	entry   commonprofile.EnvironmentEntry
}

func newEnvironmentEntryForm(editing int) *environmentEntryForm {
	return &environmentEntryForm{editing: editing, entry: commonprofile.EnvironmentEntry{
		Scope: environmentintent.ScopeAttachedProcessTree, Classification: environmentintent.ClassificationNonSecret,
		Source: commonprofile.EnvironmentSource{Kind: environmentintent.SourceHostEnvironment},
	}}
}

func (editor environmentEditor) Init() tea.Cmd { return nil }
func (editor environmentEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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
		editor.form, editor.err = newEnvironmentEntryForm(-1), ""
	case "e", "enter":
		if len(selection.Entries) != 0 {
			editor.form = newEnvironmentEntryForm(editor.cursor)
			editor.form.entry = selection.Entries[editor.cursor]
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

func (editor *environmentEditor) updateForm(press tea.KeyPressMsg) {
	form := editor.form
	switch press.String() {
	case "esc":
		editor.form, editor.err = nil, ""
	case "up":
		if form.field > 0 {
			form.field--
		}
	case "down", "tab":
		if form.field < 4 {
			form.field++
		}
	case "enter":
		if form.field < 4 {
			form.field++
			return
		}
		selection, _ := category.Selection(editor.draft, editor.binding)
		selection.Entries = append([]commonprofile.EnvironmentEntry(nil), selection.Entries...)
		if form.editing < 0 {
			selection.Entries = append(selection.Entries, form.entry)
		} else {
			selection.Entries[form.editing] = form.entry
		}
		encoded, err := commonprofile.EncodeEnvironmentSelection(selection)
		if err != nil {
			editor.err = err.Error()
			return
		}
		selection, err = commonprofile.DecodeEnvironmentSelection(encoded)
		if err != nil {
			editor.err = err.Error()
			return
		}
		if err := category.SetSelection(&editor.draft, editor.binding, selection); err != nil {
			editor.err = err.Error()
			return
		}
		editor.form, editor.err = nil, ""
	case "left", "right", "space":
		if form.field == 2 {
			if form.entry.Classification == environmentintent.ClassificationNonSecret {
				form.entry.Classification = environmentintent.ClassificationSecret
				form.entry.Source = commonprofile.EnvironmentSource{Kind: environmentintent.SourceSecretReference, Provider: environmentintent.ProviderHostEnvironment}
				form.entry.Required = true
			} else {
				form.entry.Classification = environmentintent.ClassificationNonSecret
				form.entry.Source = commonprofile.EnvironmentSource{Kind: environmentintent.SourceHostEnvironment}
				form.entry.Required = false
			}
			return
		}
		if form.field == 4 && form.entry.Classification == environmentintent.ClassificationNonSecret {
			form.entry.Required = !form.entry.Required
		}
	case "backspace":
		switch form.field {
		case 0:
			form.entry.ID = trimLastRune(form.entry.ID)
		case 1:
			form.entry.Destination = trimLastRune(form.entry.Destination)
		case 3:
			if form.entry.Classification == environmentintent.ClassificationSecret {
				form.entry.Source.Reference = trimLastRune(form.entry.Source.Reference)
			} else {
				form.entry.Source.Name = trimLastRune(form.entry.Source.Name)
			}
		}
	default:
		value := press.Key().Text
		if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
			return
		}
		switch form.field {
		case 0:
			form.entry.ID += value
		case 1:
			form.entry.Destination += value
		case 3:
			if form.entry.Classification == environmentintent.ClassificationSecret {
				form.entry.Source.Reference += value
			} else {
				form.entry.Source.Name += value
			}
		}
	}
}

func (editor environmentEditor) Draft() category.Draft { return editor.draft }
func (editor environmentEditor) WithDraft(draft category.Draft) Editor {
	editor.draft = draft
	return editor
}
func (editor environmentEditor) ListFocused() bool { return editor.form == nil }
func (editor environmentEditor) View() tea.View {
	selection, _ := category.Selection(editor.draft, editor.binding)
	if editor.form != nil {
		entry := editor.form.entry
		source := entry.Source.Name
		if entry.Classification == environmentintent.ClassificationSecret {
			source = entry.Source.Reference
		}
		labels := []string{"ID", "Destination", "Classification", "Host source/reference", "Required"}
		values := []string{entry.ID, entry.Destination, entry.Classification, source, fmt.Sprint(entry.Required)}
		var lines strings.Builder
		lines.WriteString("Scoped environment entry\n\n")
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
		lines.WriteString("\n\nEnter/Tab advances; arrows/Space change options; Enter saves; Esc cancels.")
		return tea.NewView(lines.String())
	}
	var lines strings.Builder
	lines.WriteString("Attached process environment\n\n")
	if len(selection.Entries) == 0 {
		lines.WriteString("No selected environment entries.\n")
	}
	for index, entry := range selection.Entries {
		marker := "  "
		if index == editor.cursor {
			marker = "> "
		}
		source := entry.Source.Name
		if entry.Classification == environmentintent.ClassificationSecret {
			source = "host-environment:<redacted-reference>"
		}
		fmt.Fprintf(&lines, "%s%s  %s <- %s  %s\n", marker, entry.ID, entry.Destination, source, entry.Classification)
	}
	lines.WriteString("\nA add  E/Enter edit  D delete. Values are never read or displayed here.")
	return tea.NewView(lines.String())
}

package builder

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
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

func redundantExclusionFixture(t *testing.T) (commonprofile.ExclusionsBinding, *category.Registry, category.Draft) {
	t.Helper()
	binding, err := commonprofile.NewExclusionsBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	selection := commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{
		{ID: "data", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "data"}},
		{ID: "data-cache", Type: "file", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "data/cache"}},
		{ID: "home-env", Type: "file", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: "/owner/private/.env"}},
		{ID: "home-env-upper", Type: "file", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: "/owner/private/.ENV"}},
	}}
	// Stored redundant selections remain valid drafts.
	if err := category.SetSelection(&draft, binding, selection); err != nil {
		t.Fatalf("redundant selection rejected: %v", err)
	}
	return binding, registry, draft
}

func TestExclusionsEditorWarnsAboutNestedAndCaseOnlyEntries(t *testing.T) {
	binding, _, draft := redundantExclusionFixture(t)
	editor := exclusionsEditor{draft: draft, binding: binding}
	view := editor.View().Content
	for _, want := range []string{
		"Warning: redundant entries",
		`! exclusion "data-cache" is redundant: directory exclusion "data" already covers its path`,
		`! exclusions "home-env" and "home-env-upper" differ only by letter case`,
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "/owner/private") {
		t.Fatalf("warning discloses local path:\n%s", view)
	}

	// Adding a case-only duplicate through the form keeps the entry and warns.
	editor = exclusionsEditor{draft: draft, binding: binding}
	editor = exclusionEditorPress(editor, "a")
	for _, character := range "upper" {
		editor = exclusionEditorText(editor, character)
	}
	editor = exclusionEditorPress(editor, "enter")
	editor = exclusionEditorPress(editor, "space")
	editor = exclusionEditorPress(editor, "enter")
	editor = exclusionEditorPress(editor, "enter")
	for _, character := range "DATA" {
		editor = exclusionEditorText(editor, character)
	}
	editor = exclusionEditorPress(editor, "enter")
	if editor.form != nil || editor.err != "" {
		t.Fatalf("case-only duplicate was rejected: %q", editor.err)
	}
	if view := editor.View().Content; !strings.Contains(view, `exclusions "data" and "upper" differ only by letter case`) {
		t.Fatalf("case-only duplicate not reported:\n%s", view)
	}

	empty := exclusionsEditor{draft: category.Draft{}, binding: binding}
	if advisories := empty.Advisories(); advisories != nil {
		t.Fatalf("invalid draft advisories = %q", advisories)
	}
}

func TestMutationPreviewShowsExclusionWarningsWithoutBlockingCommit(t *testing.T) {
	binding, registry, draft := redundantExclusionFixture(t)
	registration, err := RegisterExclusionsEditor(binding)
	if err != nil {
		t.Fatal(err)
	}
	editors, err := NewEditorRegistry(registry, registration)
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewModel("redundant", draft, editors)
	if err != nil {
		t.Fatal(err)
	}
	model, err = model.WithMutation(MutationOptions{Label: "Edit", Compact: true, Prepare: func(category.Draft) (PreparedMutation, error) {
		return PreparedMutation{Text: "preview", Save: func(context.Context, category.Draft) (string, error) { return "", nil }}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(model.prepared.Text, "Warnings (non-blocking; the Profile is saved as shown):") || !strings.Contains(model.prepared.Text, `exclusion "data-cache" is redundant`) {
		t.Fatalf("preview = %q", model.prepared.Text)
	}
	if model.prepared.Warning {
		t.Fatal("redundancy warnings must not require acknowledgement")
	}
	if strings.Contains(model.prepared.Text, "/owner/private") {
		t.Fatalf("preview discloses local path: %q", model.prepared.Text)
	}
	if footer := model.View().Content; !strings.Contains(footer, "Y/Enter commit") {
		t.Fatalf("commit not offered:\n%s", footer)
	}
}

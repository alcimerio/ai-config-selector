package builder

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"strings"
	"testing"
)

func TestSavedUnavailableSelectionVisibleAndRemovable(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	reference := skills.SkillReference{Source: "devin-config", RelativePath: "lost"}
	if err := category.SetSelection(&draft, binding, []skills.SkillReference{reference}); err != nil {
		t.Fatal(err)
	}
	for _, discovered := range []bool{false, true} {
		seed, err := draft.Clone()
		if err != nil {
			t.Fatal(err)
		}
		editor := NewSkillsEditor(seed, binding)
		if discovered {
			editor = editor.WithCatalog(nil)
		}
		if view := editor.View().Content; !strings.Contains(view, "[x] lost") {
			t.Fatalf("discovered=%v: saved reference invisible: %s", discovered, view)
		}
		updated, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
		remaining, err := category.Selection(updated.(skillsEditor).Draft(), binding)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("cannot explicitly remove unavailable selection: %v %v", remaining, err)
		}
	}
}

func TestRepairSelectionsRetainIdentityAcrossSearchResizeRefreshAndReplacement(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	old := skills.SkillReference{Source: "devin-config", RelativePath: "review"}
	replacement := skills.SkillReference{Source: "shared-agents", RelativePath: "review"}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, []skills.SkillReference{old}); err != nil {
		t.Fatal(err)
	}
	model := newLoadedSkillsModel(t, "repair", draft, registry, binding, []skills.SkillBundle{{Reference: replacement, DisplayName: "review"}})
	options := MutationOptions{Label: "Edit", Prepare: func(category.Draft) (PreparedMutation, error) {
		return PreparedMutation{Text: "preview", Save: func(context.Context, category.Draft) (string, error) { return "", nil }}, nil
	}}
	var err error
	model, err = model.WithMutation(options)
	if err != nil {
		t.Fatal(err)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if view := model.View().Content; !strings.Contains(view, "[x] review [devin-config:review] missing") || !strings.Contains(view, "[ ] review [shared-agents:review] available") {
		t.Fatalf("identity union: %s", view)
	}
	for _, event := range []tea.Msg{tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}), tea.KeyPressMsg(tea.Key{Code: 'z', Text: "zzzz"}), tea.WindowSizeMsg{Width: 20, Height: 5}, tea.WindowSizeMsg{Width: 100, Height: 30}, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}), tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}), tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})} {
		model = update(t, model, event)
	}
	refs, _ := category.Selection(model.draft, binding)
	if len(refs) != 1 || refs[0] != old {
		t.Fatalf("navigation rebound selection: %v", refs)
	}
	// Remove the unavailable exact identity and explicitly select the other source.
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	// The missing unselected row disappears; replacement is now cursor zero.
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	refs, _ = category.Selection(model.draft, binding)
	if len(refs) != 1 || refs[0] != replacement {
		t.Fatalf("replacement: %v", refs)
	}
	// Refresh failure retains selection and allows explicit repair without discovery.
	refreshed, command := model.Update(tea.KeyPressMsg(tea.Key{Code: 'r', Text: "r"}))
	model = refreshed.(Model)
	if command == nil {
		t.Fatal("refresh missing")
	}
	model = update(t, model, discoveryCompletedMsg{categoryID: "skills", err: errors.New("source unavailable")})
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'e', Text: "e"}))
	if view := model.View().Content; !strings.Contains(view, "[x] review") || !strings.Contains(view, "unavailable/unchecked") {
		t.Fatalf("failed discovery lost selection: %s", view)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	refs, _ = category.Selection(model.draft, binding)
	if len(refs) != 0 {
		t.Fatalf("failed-source removal: %v", refs)
	}
}

func TestAmbiguousSavedSelectionNeverRebindsAndRemainsRemovable(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	ref := skills.SkillReference{Source: "devin-config", RelativePath: "same"}
	if err := category.SetSelection(&draft, binding, []skills.SkillReference{ref}); err != nil {
		t.Fatal(err)
	}
	editor := NewSkillsEditor(draft, binding, []skills.SkillBundle{{Reference: ref, DisplayName: "one"}, {Reference: ref, DisplayName: "two"}})
	if len(editor.rows()) != 1 || !strings.Contains(editor.View().Content, "ambiguous") || len(editor.Unresolved()) != 1 {
		t.Fatalf("ambiguous identity was rebound: %s", editor.View().Content)
	}
	changed, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
	remaining, _ := category.Selection(changed.(skillsEditor).draft, binding)
	if len(remaining) != 0 {
		t.Fatal("ambiguous selection cannot be removed")
	}
}

func TestMutationPreviewWarningSnapshotAndCancellationBoundaries(t *testing.T) {
	for _, boundary := range []string{"overview", "preview", "warning", "discard"} {
		t.Run(boundary, func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			draft := registry.NewDraft()
			ref := skills.SkillReference{Source: "devin-config", RelativePath: "lost"}
			if err := category.SetSelection(&draft, binding, []skills.SkillReference{ref}); err != nil {
				t.Fatal(err)
			}
			model := newLoadedSkillsModel(t, "repair", draft, registry, binding, nil)
			saves := 0
			var err error
			model, err = model.WithMutation(MutationOptions{Label: "Edit", Prepare: func(category.Draft) (PreparedMutation, error) {
				return PreparedMutation{Text: "exact bytes", Save: func(context.Context, category.Draft) (string, error) { saves++; return "saved", nil }}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if boundary == "discard" {
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))
			}
			if boundary == "preview" || boundary == "warning" {
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
				if model.screen != mutationPreviewScreen {
					t.Fatal("preview bypassed")
				}
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
				if saves != 0 || model.screen != mutationPreviewScreen {
					t.Fatal("warning bypassed")
				}
				if boundary == "warning" {
					model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'a', Text: "a"}))
				}
			}
			model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
			if model.screen == discardScreen {
				model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
			}
			if !model.Outcome().Cancelled || saves != 0 {
				t.Fatalf("cancellation boundary: %v saves %d", model.Outcome(), saves)
			}
		})
	}
}

func TestMutationConflictPreservesDraftAndRequiresExplicitReload(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, []skills.SkillReference{{Source: "devin-config", RelativePath: "lost"}}); err != nil {
		t.Fatal(err)
	}
	initial, _ := draft.Clone()
	model := newLoadedSkillsModel(t, "repair", draft, registry, binding, nil)
	saves, reloads := 0, 0
	var err error
	model, err = model.WithMutation(MutationOptions{Label: "Edit", Prepare: func(category.Draft) (PreparedMutation, error) {
		return PreparedMutation{Text: "preview", Save: func(context.Context, category.Draft) (string, error) {
			saves++
			return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.NotCommitted}, Err: profilerepo.ErrConflict}
		}}, nil
	}, Reload: func(context.Context) (category.Draft, error) { reloads++; return registry.NewDraft(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	model.overviewCursor = 1
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'a', Text: "a"}))
	updated, save := model.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	model = updated.(Model)
	if save == nil {
		t.Fatal("confirmed preview has no save")
	}
	model = update(t, model, save())
	for _, key := range []tea.Key{{Code: 'r', Text: "r"}, {Code: tea.KeyEnter}, {Code: tea.KeySpace}} {
		model = update(t, model, tea.KeyPressMsg(key))
	}
	if saves != 1 || !model.draft.Equal(initial) || reloads != 0 {
		t.Fatalf("blind retry/draft loss: saves %d reloads %d", saves, reloads)
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'l', Text: "l"}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if reloads != 0 || !model.draft.Equal(initial) {
		t.Fatal("reload decline lost draft")
	}
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'l', Text: "l"}))
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
	if reloads != 1 || model.screen != overviewScreen || model.draft.Summaries()[0].Count != 0 {
		t.Fatal("explicit reload failed")
	}
	if saves != 1 {
		t.Fatal("reload implicitly committed")
	}
}

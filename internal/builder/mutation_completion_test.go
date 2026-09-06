package builder

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestDiscoveryCompletionPreservesDiscardAndReturnScreen(t *testing.T) {
	for _, failure := range []string{"success", "discovery error", "decode error"} {
		for _, response := range []string{"accept", "decline", "decline then retry"} {
			t.Run(failure+"/"+response, func(t *testing.T) {
				binding, registry := newBuilderFixture(t)
				draft := registry.NewDraft()
				ref := skills.SkillReference{Source: "devin-config", RelativePath: "lost"}
				if err := category.SetSelection(&draft, binding, []skills.SkillReference{ref}); err != nil {
					t.Fatal(err)
				}
				m := newLoadedSkillsModel(t, "repair", draft, registry, binding, nil)
				m, err := m.WithMutation(MutationOptions{Label: "Edit", Prepare: func(category.Draft) (PreparedMutation, error) {
					return PreparedMutation{Text: "preview", Save: func(context.Context, category.Draft) (string, error) { t.Fatal("discard published"); return "", nil }}, nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				m = update(t, m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
				m = update(t, m, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace}))
				dirty, _ := m.draft.Clone()
				m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'r', Text: "r"}))
				m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
				completion := discoveryCompletedMsg{categoryID: "skills", discovered: []skills.SkillBundle{}}
				wantReturn := categoryScreen
				if failure == "discovery error" {
					completion.err = errors.New("unavailable")
					wantReturn = loadFailureScreen
				}
				if failure == "decode error" {
					completion.discovered = "invalid catalog"
					wantReturn = loadFailureScreen
				}
				m = update(t, m, completion)
				if m.screen != discardScreen || !strings.Contains(m.View().Content, "Discard changes?") || !m.draft.Equal(dirty) {
					t.Fatalf("completion replaced discard or changed draft: %s", m.View().Content)
				}
				if response == "accept" {
					m = update(t, m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
					if !m.Outcome().Cancelled {
						t.Fatal("discard was not confirmed")
					}
					return
				}
				m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
				if m.screen != wantReturn || !m.draft.Equal(dirty) {
					t.Fatalf("decline returned to stale screen %v", m.screen)
				}
				if response == "decline then retry" {
					m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'r', Text: "r"}))
					m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
					m = update(t, m, discoveryCompletedMsg{categoryID: "skills", discovered: []skills.SkillBundle{}})
					m = update(t, m, tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"}))
					if !m.Outcome().Cancelled {
						t.Fatal("retry completion lost cancellation")
					}
				}
			})
		}
	}
}

func TestHandledSaveFailureDoesNotRemainShutdownOutcome(t *testing.T) {
	for _, failure := range []error{profilerepo.ErrConflict, errors.New("ordinary failure"), context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			m := newLoadedSkillsModel(t, "repair", registry.NewDraft(), registry, binding, nil)
			gate := &saveRuntime{}
			m.runtimeSaves = gate
			m = m.WithSaver(func(context.Context, category.Draft) (string, error) {
				return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.NotCommitted}, Err: failure}
			})
			started, save := m.startSave()
			m = started.(Model)
			m = update(t, m, save())
			if m.screen != saveFailureScreen || !errors.Is(m.saveError, failure) {
				t.Fatal("failure not handled by model")
			}
			if result := gate.settle(); result != nil {
				t.Fatalf("handled failure resurrected at shutdown: %v", result.err)
			}
		})
	}
}

func TestHandledTerminalSaveOutcomesRemainAvailableAtShutdown(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.Committed, profilerepo.Unknown, profilerepo.NotCommitted} {
		t.Run(string(state), func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			m := newLoadedSkillsModel(t, "repair", registry.NewDraft(), registry, binding, nil)
			gate := &saveRuntime{}
			m.runtimeSaves = gate
			failure := &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: state, RecoveryRequired: true}, Err: context.Canceled}
			m = m.WithSaver(func(context.Context, category.Draft) (string, error) { return "", failure })
			started, save := m.startSave()
			m = update(t, started.(Model), save())
			if m.Outcome().Cancelled || m.terminalError != failure {
				t.Fatal("terminal outcome became ordinary failure/cancellation")
			}
			settled := gate.settle()
			if settled == nil || settled.err != failure {
				t.Fatal("terminal settlement was retired")
			}
		})
	}
}

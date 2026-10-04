package builder

import (
	"context"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
)

func TestCreationRequiresExplicitDevelopmentAndCapturesSharedTargets(t *testing.T) {
	var saved CreationOptions
	var preset bool
	m := Model{}.WithCreation(func(_ context.Context, _ category.Draft, options CreationOptions) (string, error) {
		saved = options
		return "profile", nil
	}, func(_ *category.Draft, development bool) error { preset = development; return nil })
	key := func(code rune) { next, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: code})); m = next.(Model) }
	if m.creation.Development || m.creation.Devin || m.creation.Codex {
		t.Fatal("creation default expands authority")
	}
	key(tea.KeySpace)
	key(tea.KeyDown)
	key(tea.KeySpace)
	key(tea.KeyDown)
	key(tea.KeySpace)
	key(tea.KeyDown)
	key(tea.KeyEnter)
	if m.screen != overviewScreen || !preset {
		t.Fatal("development selection not applied")
	}
	if _, err := m.save(context.Background(), m.draft); err != nil {
		t.Fatal(err)
	}
	if !saved.Devin || !saved.Codex || !saved.Development {
		t.Fatalf("saved %+v", saved)
	}
}
func TestCreationCancelNeverAppliesPresetOrSaves(t *testing.T) {
	m := Model{}.WithCreation(func(context.Context, category.Draft, CreationOptions) (string, error) {
		t.Fatal("saved cancelled creation")
		return "", nil
	}, func(*category.Draft, bool) error { t.Fatal("applied cancelled preset"); return nil })
	next, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if !next.(Model).outcome.Cancelled {
		t.Fatal("not cancelled")
	}
}

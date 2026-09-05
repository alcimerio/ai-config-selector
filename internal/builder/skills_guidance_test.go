package builder

import (
	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"strings"
	"testing"
)

func TestSkillsEmptyCatalogAndEmptySearchGuidance(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	empty := NewSkillsEditor(registry.NewDraft(), binding)
	for _, want := range []string{"No Skills discovered", "~/.config/devin/skills", "~/.agents/skills", "name/SKILL.md"} {
		if !strings.Contains(empty.View().Content, want) {
			t.Errorf("empty catalog omits %q: %s", want, empty.View().Content)
		}
	}
	editor := NewSkillsEditor(registry.NewDraft(), binding, []skills.SkillBundle{{DisplayName: "review", Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "review"}}})
	model, _ := editor.Update(tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"}))
	model, _ = model.Update(tea.KeyPressMsg(tea.Key{Code: 'z', Text: "zzzz"}))
	if view := model.View().Content; !strings.Contains(view, "No matching Skills") || !strings.Contains(view, "Esc to clear") || strings.Contains(view, "No Skills discovered") {
		t.Fatalf("filtered guidance: %s", view)
	}
	model, _ = model.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if view := model.View().Content; !strings.Contains(view, "review") || strings.Contains(view, "No matching Skills") {
		t.Fatalf("clear did not restore catalog: %s", view)
	}
}

package builder

import (
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// NewSkillsEditor constructs the Skills child model. It never starts a
// Bubble Tea program; the root model remains the runtime owner.
func NewSkillsEditor[C launch.Contribution](draft category.Draft, binding category.Binding[[]skills.SkillReference, []skills.SkillBundle, C], catalog []skills.SkillBundle) skillsEditor {
	return skillsEditor{
		draft: draft,
		selection: func(draft category.Draft) ([]skills.SkillReference, error) {
			return category.Selection(draft, binding)
		},
		setSelection: func(draft *category.Draft, selection []skills.SkillReference) error {
			return category.SetSelection(draft, binding, selection)
		},
		id:      binding.ID(),
		catalog: append([]skills.SkillBundle(nil), catalog...),
	}
}

type skillsEditor struct {
	draft        category.Draft
	selection    func(category.Draft) ([]skills.SkillReference, error)
	setSelection func(*category.Draft, []skills.SkillReference) error
	id           string
	catalog      []skills.SkillBundle
	cursor       int
}

func (m skillsEditor) ID() string            { return m.id }
func (m skillsEditor) Draft() category.Draft { return m.draft }
func (m skillsEditor) Init() tea.Cmd         { return nil }

func (m skillsEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch {
	case key.Matches(press, controls.up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(press, controls.down):
		if m.cursor < len(m.catalog)-1 {
			m.cursor++
		}
	case key.Matches(press, controls.toggle):
		if len(m.catalog) != 0 {
			m.toggle(m.catalog[m.cursor].Reference)
		}
	}
	return m, nil
}

func (m *skillsEditor) toggle(reference skills.SkillReference) {
	selected, err := m.selection(m.draft)
	if err != nil {
		return
	}
	for index, current := range selected {
		if current == reference {
			selected = append(selected[:index], selected[index+1:]...)
			_ = m.setSelection(&m.draft, selected)
			return
		}
	}
	selected = append(selected, reference)
	_ = m.setSelection(&m.draft, selected)
}

func (m skillsEditor) View() tea.View {
	var content strings.Builder
	content.WriteString("Skills\n\n")
	for index, bundle := range m.catalog {
		marker := "  "
		if index == m.cursor {
			marker = "> "
		}
		selected := "[ ]"
		if m.isSelected(bundle.Reference) {
			selected = "[x]"
		}
		content.WriteString(marker + selected + " " + safe(bundle.DisplayName) + " [" + safe(string(bundle.Reference.Source)) + "]\n")
	}
	content.WriteString("\nUp/Down navigate  Space/Enter toggle  Left/Esc back")
	return tea.NewView(content.String())
}

func (m skillsEditor) isSelected(reference skills.SkillReference) bool {
	selected, err := m.selection(m.draft)
	if err != nil {
		return false
	}
	for _, current := range selected {
		if current == reference {
			return true
		}
	}
	return false
}

func safe(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

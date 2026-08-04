// Package builder implements the interactive Profile Builder boundary.
package builder

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// Outcome is the terminal result selected by a Profile Builder session.
type Outcome struct {
	Draft     category.Draft
	Create    bool
	Cancelled bool
}

// Model is the root Bubble Tea model. It owns the Profile Draft and all
// navigation state; category editors are represented inside this one program.
type Model struct {
	name           string
	draft          category.Draft
	selection      func(category.Draft) ([]skills.SkillReference, error)
	setSelection   func(*category.Draft, []skills.SkillReference) error
	catalog        []skills.SkillBundle
	screen         screen
	overviewCursor int
	skillsCursor   int
	outcome        Outcome
}

type screen int

const (
	overviewScreen screen = iota
	skillsScreen
	confirmScreen
)

var controls = struct {
	up, down, open, back, toggle, cancel, accept, decline key.Binding
}{
	up:      key.NewBinding(key.WithKeys("up"), key.WithHelp("Up", "navigate")),
	down:    key.NewBinding(key.WithKeys("down"), key.WithHelp("Down", "navigate")),
	open:    key.NewBinding(key.WithKeys("space", "enter", "right"), key.WithHelp("Space/Enter/Right", "open")),
	back:    key.NewBinding(key.WithKeys("left", "esc"), key.WithHelp("Left/Esc", "back")),
	toggle:  key.NewBinding(key.WithKeys("space", "enter"), key.WithHelp("Space/Enter", "toggle")),
	cancel:  key.NewBinding(key.WithKeys("esc"), key.WithHelp("Esc", "cancel")),
	accept:  key.NewBinding(key.WithKeys("y", "enter"), key.WithHelp("Y/Enter", "create")),
	decline: key.NewBinding(key.WithKeys("n", "esc", "left"), key.WithHelp("N/Esc", "return")),
}

// NewModel constructs the root model with a discovered Skills catalog.
func NewModel[C launch.Contribution](name string, draft category.Draft, binding category.Binding[[]skills.SkillReference, []skills.SkillBundle, C], catalog []skills.SkillBundle) Model {
	return Model{
		name:  name,
		draft: draft,
		selection: func(draft category.Draft) ([]skills.SkillReference, error) {
			return category.Selection(draft, binding)
		},
		setSelection: func(draft *category.Draft, selection []skills.SkillReference) error {
			return category.SetSelection(draft, binding, selection)
		},
		catalog: append([]skills.SkillBundle(nil), catalog...),
		screen:  overviewScreen,
	}
}

// Init starts no nested programs or background work in the initial slice.
func (m Model) Init() tea.Cmd { return nil }

// Update applies user input to the root builder state.
func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}

	switch m.screen {
	case overviewScreen:
		return m.updateOverview(key)
	case skillsScreen:
		return m.updateSkills(key)
	case confirmScreen:
		return m.updateConfirmation(key)
	default:
		return m, nil
	}
}

func (m Model) updateOverview(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(press, controls.up):
		if m.overviewCursor > 0 {
			m.overviewCursor--
		}
	case key.Matches(press, controls.down):
		if m.overviewCursor < 2 {
			m.overviewCursor++
		}
	case key.Matches(press, controls.open):
		switch m.overviewCursor {
		case 0:
			m.screen = skillsScreen
		case 1:
			if m.selectionCount() == 0 {
				m.screen = confirmScreen
				return m, nil
			}
			m.outcome = Outcome{Draft: m.draft, Create: true}
			return m, tea.Quit
		case 2:
			m.outcome = Outcome{Draft: m.draft, Cancelled: true}
			return m, tea.Quit
		}
	case key.Matches(press, controls.cancel):
		m.outcome = Outcome{Draft: m.draft, Cancelled: true}
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) updateSkills(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(press, controls.up):
		if m.skillsCursor > 0 {
			m.skillsCursor--
		}
	case key.Matches(press, controls.down):
		if m.skillsCursor < len(m.catalog)-1 {
			m.skillsCursor++
		}
	case key.Matches(press, controls.back):
		m.screen = overviewScreen
	case key.Matches(press, controls.toggle):
		if len(m.catalog) != 0 {
			m.toggleSkill(m.catalog[m.skillsCursor].Reference)
		}
	}
	return m, nil
}

func (m Model) updateConfirmation(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(press, controls.accept):
		m.outcome = Outcome{Draft: m.draft, Create: true}
		return m, tea.Quit
	case key.Matches(press, controls.decline):
		m.screen = overviewScreen
	}
	return m, nil
}

func (m *Model) toggleSkill(reference skills.SkillReference) {
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

func (m Model) selectionCount() int {
	for _, summary := range m.draft.Summaries() {
		if summary.ID == "skills" {
			return summary.Count
		}
	}
	return 0
}

// Outcome returns the current terminal outcome, if any.
func (m Model) Outcome() Outcome { return m.outcome }

// Run starts the sole Bubble Tea program for a Profile Builder session.
func Run(ctx context.Context, model Model, input io.Reader, output io.Writer) (Outcome, error) {
	program := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(input), tea.WithOutput(output))
	completed, err := program.Run()
	if err != nil {
		return Outcome{}, err
	}
	final, ok := completed.(Model)
	if !ok {
		return Outcome{}, fmt.Errorf("Profile Builder returned %T, not its root model", completed)
	}
	return final.Outcome(), nil
}

// View renders the single alternate-screen builder UI.
func (m Model) View() tea.View {
	var content strings.Builder
	switch m.screen {
	case overviewScreen:
		content.WriteString("Create Profile \"")
		content.WriteString(m.name)
		content.WriteString("\"\n\n")
		rows := []string{
			"Skills                         " + plural(m.selectionCount(), "selected"),
			"Create Profile",
			"Cancel",
		}
		for index, row := range rows {
			marker := "  "
			if index == m.overviewCursor {
				marker = "> "
			}
			content.WriteString(marker + row + "\n")
		}
		content.WriteString("\nUp/Down navigate  Space/Enter/Right open  Esc cancel")
	case skillsScreen:
		content.WriteString("Skills\n\n")
		for index, bundle := range m.catalog {
			marker := "  "
			if index == m.skillsCursor {
				marker = "> "
			}
			selected := "[ ]"
			if m.isSelected(bundle.Reference) {
				selected = "[x]"
			}
			content.WriteString(marker + selected + " " + safe(bundle.DisplayName) + " [" + safe(string(bundle.Reference.Source)) + "]\n")
		}
		content.WriteString("\nUp/Down navigate  Space/Enter toggle  Left/Esc back")
	case confirmScreen:
		content.WriteString("Create an empty Profile?\n\nThis Profile will not select any Skills.\n\nY/Enter create  N/Esc return")
	}
	view := tea.NewView(content.String())
	view.AltScreen = true
	return view
}

func (m Model) isSelected(reference skills.SkillReference) bool {
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

func plural(count int, suffix string) string {
	return strconv.Itoa(count) + " " + suffix
}

func safe(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

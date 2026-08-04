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
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// Outcome is the terminal result selected by a Profile Builder session.
type Outcome struct {
	Draft     category.Draft
	Create    bool
	Cancelled bool
}

// Model is the root Bubble Tea model. It owns navigation, dimensions, the
// Profile Draft, modal state, and the one child category editor.
type Model struct {
	name           string
	draft          category.Draft
	editor         categoryEditor
	loadCatalog    func(context.Context) ([]skills.SkillBundle, error)
	loadState      loadState
	loadError      error
	confirmFailed  bool
	screen         screen
	overviewCursor int
	width          int
	height         int
	outcome        Outcome
}

type loadState int

const (
	unloaded loadState = iota
	loading
	loaded
	loadFailed
)

type catalogLoadedMsg struct {
	catalog []skills.SkillBundle
	err     error
}

type screen int

const (
	overviewScreen screen = iota
	skillsScreen
	confirmScreen
)

type categoryEditor interface {
	tea.Model
	ID() string
	Draft() category.Draft
	ListFocused() bool
}

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

// NewModel constructs the root model around one category child model.
func NewModel(name string, draft category.Draft, editor categoryEditor, loadCatalog ...func(context.Context) ([]skills.SkillBundle, error)) Model {
	model := Model{name: name, draft: draft, editor: editor, screen: overviewScreen, loadState: loaded}
	if len(loadCatalog) != 0 {
		model.loadCatalog = loadCatalog[0]
		model.loadState = unloaded
	}
	return model
}

// Init starts no nested programs or background work in this initial slice.
func (m Model) Init() tea.Cmd { return nil }

// Update applies terminal and user events to the root builder state.
func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case catalogLoadedMsg:
		if message.err != nil {
			m.loadState = loadFailed
			m.loadError = message.err
			return m, nil
		}
		if editor, ok := m.editor.(skillsEditor); ok {
			m.editor = editor.WithCatalog(message.catalog)
		}
		m.loadState, m.loadError, m.screen = loaded, nil, skillsScreen
		return m, nil
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		return m, nil
	case tea.KeyPressMsg:
		switch m.screen {
		case overviewScreen:
			return m.updateOverview(message)
		case skillsScreen:
			return m.updateEditor(message)
		case confirmScreen:
			return m.updateConfirmation(message)
		}
	}
	return m, nil
}

func (m Model) updateOverview(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	categories := m.categories()
	switch {
	case key.Matches(press, controls.up):
		if m.overviewCursor > 0 {
			m.overviewCursor--
		}
	case key.Matches(press, controls.down):
		if m.overviewCursor < len(categories)+1 {
			m.overviewCursor++
		}
	case key.Matches(press, controls.open):
		switch m.overviewCursor {
		case len(categories):
			if m.loadState == loadFailed {
				m.confirmFailed = true
				m.screen = confirmScreen
				return m, nil
			}
			if m.selectedCount() == 0 {
				m.screen = confirmScreen
				return m, nil
			}
			m.outcome = Outcome{Draft: m.draft, Create: true}
			return m, tea.Quit
		case len(categories) + 1:
			m.outcome = Outcome{Draft: m.draft, Cancelled: true}
			return m, tea.Quit
		default:
			if categories[m.overviewCursor].ID == m.editor.ID() {
				if m.loadState == unloaded || m.loadState == loadFailed {
					m.loadState = loading
					return m, m.discoveryCommand()
				}
				if m.loadState == loaded {
					m.screen = skillsScreen
				}
			}
		}
	case key.Matches(press, controls.cancel):
		m.outcome = Outcome{Draft: m.draft, Cancelled: true}
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) updateEditor(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.editor.ListFocused() && key.Matches(press, controls.back) {
		m.draft = m.editor.Draft()
		m.screen = overviewScreen
		return m, nil
	}
	updated, command := m.editor.Update(press)
	editor, ok := updated.(categoryEditor)
	if !ok {
		return m, nil
	}
	m.editor = editor
	m.draft = editor.Draft()
	return m, command
}

func (m Model) discoveryCommand() tea.Cmd {
	return func() tea.Msg {
		catalog, err := m.loadCatalog(context.Background())
		return catalogLoadedMsg{catalog: catalog, err: err}
	}
}

func (m Model) updateConfirmation(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(press, controls.accept):
		if m.confirmFailed {
			m.confirmFailed = false
			if m.selectedCount() == 0 {
				return m, nil
			}
		}
		m.outcome = Outcome{Draft: m.draft, Create: true}
		return m, tea.Quit
	case key.Matches(press, controls.decline):
		m.screen = overviewScreen
	}
	return m, nil
}

func (m Model) selectedCount() int {
	count := 0
	for _, summary := range m.categories() {
		count += summary.Count
	}
	return count
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
		categories := m.categories()
		rows := make([]string, 0, len(categories)+2)
		for _, summary := range categories {
			rows = append(rows, categoryName(summary.ID)+"                         "+plural(summary.Count, "selected"))
		}
		rows = append(rows, "Create Profile", "Cancel")
		for index, row := range rows {
			marker := "  "
			if index == m.overviewCursor {
				marker = "> "
			}
			content.WriteString(marker + row + "\n")
		}
		content.WriteString("\nUp/Down navigate  Space/Enter/Right open  Esc cancel")
	case skillsScreen:
		content.WriteString(m.editor.View().Content)
	case confirmScreen:
		if m.confirmFailed {
			content.WriteString("Skills failed to load. Create Profile anyway?\n\nY/Enter create  N/Esc return")
		} else {
			content.WriteString("Create an empty Profile?\n\nThis Profile will not select any Skills.\n\nY/Enter create  N/Esc return")
		}
	}
	if m.screen == overviewScreen && m.loadState == loading {
		content.WriteString("\nLoading Skills...\n")
	}
	if m.screen == overviewScreen && m.loadState == loadFailed {
		content.WriteString("\nSkills failed to load. Space/Enter retry  Esc back\n")
	}
	view := tea.NewView(content.String())
	view.AltScreen = true
	return view
}

func plural(count int, suffix string) string { return strconv.Itoa(count) + " " + suffix }

func categoryName(id string) string {
	words := strings.FieldsFunc(id, func(character rune) bool { return character == '-' || character == '_' })
	for index, word := range words {
		if word != "" {
			words[index] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func (m Model) categories() []category.Summary { return m.draft.Summaries() }

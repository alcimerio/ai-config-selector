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

// SaveFunc persists one immutable Profile Draft snapshot and returns its path.
type SaveFunc func(context.Context, category.Draft) (string, error)

// Outcome is the terminal result selected by a Profile Builder session.
type Outcome struct {
	Draft     category.Draft
	Path      string
	Create    bool
	Cancelled bool
}

// Model is the root Bubble Tea model. It owns navigation, dimensions, the
// Profile Draft, modal state, and the one child category editor.
type Model struct {
	name           string
	draft          category.Draft
	initialDraft   category.Draft
	initialValid   bool
	editor         categoryEditor
	loadCatalog    func(context.Context) ([]skills.SkillBundle, error)
	context        context.Context
	save           SaveFunc
	saveCancel     context.CancelFunc
	loadState      loadState
	loadError      error
	confirmFailed  bool
	screen         screen
	returnScreen   screen
	overviewCursor int
	width          int
	height         int
	saveError      error
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

type saveCompletedMsg struct {
	draft category.Draft
	path  string
	err   error
}

type screen int

const (
	overviewScreen screen = iota
	skillsScreen
	confirmScreen
	loadingScreen
	loadFailureScreen
	savingScreen
	cancellingSaveScreen
	saveFailureScreen
	discardScreen
)

type categoryEditor interface {
	tea.Model
	ID() string
	Draft() category.Draft
	ListFocused() bool
}

var controls = struct {
	up, down, open, back, toggle, cancel, accept, decline, retry key.Binding
}{
	up:      key.NewBinding(key.WithKeys("up"), key.WithHelp("Up", "navigate")),
	down:    key.NewBinding(key.WithKeys("down"), key.WithHelp("Down", "navigate")),
	open:    key.NewBinding(key.WithKeys("space", "enter", "right"), key.WithHelp("Space/Enter/Right", "open")),
	back:    key.NewBinding(key.WithKeys("left", "esc"), key.WithHelp("Left/Esc", "back")),
	toggle:  key.NewBinding(key.WithKeys("space", "enter"), key.WithHelp("Space/Enter", "toggle")),
	cancel:  key.NewBinding(key.WithKeys("esc"), key.WithHelp("Esc", "cancel")),
	accept:  key.NewBinding(key.WithKeys("y", "enter"), key.WithHelp("Y/Enter", "confirm")),
	decline: key.NewBinding(key.WithKeys("n", "esc", "left"), key.WithHelp("N/Esc", "return")),
	retry:   key.NewBinding(key.WithKeys("r", "enter", "space"), key.WithHelp("R/Enter", "retry")),
}

// NewModel constructs the root model around one category child model.
func NewModel(name string, draft category.Draft, editor categoryEditor, loadCatalog ...func(context.Context) ([]skills.SkillBundle, error)) Model {
	initial, err := draft.Clone()
	initialValid := err == nil
	if err != nil {
		initial = draft
	}
	model := Model{name: name, draft: draft, initialDraft: initial, initialValid: initialValid, editor: editor, screen: overviewScreen, loadState: loaded, context: context.Background()}
	if len(loadCatalog) != 0 {
		model.loadCatalog = loadCatalog[0]
		model.loadState = unloaded
	}
	return model
}

// WithSaver installs the persistence boundary run by the root model.
func (m Model) WithSaver(save SaveFunc) Model { m.save = save; return m }

// WithContext supplies cancellation to asynchronous discovery.
func (m Model) WithContext(ctx context.Context) Model {
	if ctx != nil {
		m.context = ctx
	}
	return m
}

// Init starts no background work before the user makes a choice.
func (m Model) Init() tea.Cmd { return nil }

// Update applies terminal and user events to the root builder state.
func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case catalogLoadedMsg:
		if m.screen != loadingScreen {
			return m, nil
		}
		if message.err != nil {
			m.loadState, m.loadError, m.screen = loadFailed, message.err, loadFailureScreen
			return m, nil
		}
		if editor, ok := m.editor.(skillsEditor); ok {
			m.editor = editor.WithCatalog(message.catalog)
		}
		m.loadState, m.loadError, m.screen = loaded, nil, skillsScreen
		return m, nil
	case saveCompletedMsg:
		if m.screen != savingScreen && m.screen != cancellingSaveScreen {
			return m, nil
		}
		m.saveCancel = nil
		if m.screen == cancellingSaveScreen && message.err != nil {
			m.screen = overviewScreen
			return m.beginCancellation()
		}
		if message.err != nil {
			m.saveError, m.screen = message.err, saveFailureScreen
			return m, nil
		}
		m.outcome = Outcome{Draft: message.draft, Path: message.path, Create: true}
		return m, tea.Quit
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		return m, nil
	case tea.KeyPressMsg:
		if message.String() == "ctrl+c" && m.screen == savingScreen {
			m.saveCancel()
			m.screen = cancellingSaveScreen
			return m, nil
		}
		if message.String() == "ctrl+c" && m.screen != cancellingSaveScreen && m.screen != discardScreen {
			return m.beginCancellation()
		}
		switch m.screen {
		case overviewScreen:
			return m.updateOverview(message)
		case skillsScreen:
			return m.updateEditor(message)
		case confirmScreen:
			return m.updateConfirmation(message)
		case loadFailureScreen:
			return m.updateLoadFailure(message)
		case saveFailureScreen:
			return m.updateSaveFailure(message)
		case discardScreen:
			return m.updateDiscard(message)
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
				m.confirmFailed, m.screen = true, confirmScreen
				return m, nil
			}
			if m.selectedCount() == 0 {
				m.screen = confirmScreen
				return m, nil
			}
			return m.startSave()
		case len(categories) + 1:
			return m.beginCancellation()
		default:
			if categories[m.overviewCursor].ID == m.editor.ID() {
				if m.loadState == unloaded || m.loadState == loadFailed {
					m.loadState, m.screen = loading, loadingScreen
					return m, m.discoveryCommand()
				}
				if m.loadState == loaded {
					m.screen = skillsScreen
				}
			}
		}
	case key.Matches(press, controls.cancel):
		return m.beginCancellation()
	}
	return m, nil
}

func (m Model) updateEditor(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.editor.ListFocused() && key.Matches(press, controls.back) {
		m.draft, m.screen = m.editor.Draft(), overviewScreen
		return m, nil
	}
	updated, command := m.editor.Update(press)
	editor, ok := updated.(categoryEditor)
	if !ok {
		return m, nil
	}
	m.editor, m.draft = editor, editor.Draft()
	return m, command
}

func (m Model) discoveryCommand() tea.Cmd {
	loader, ctx := m.loadCatalog, m.context
	return func() tea.Msg {
		catalog, err := loader(ctx)
		return catalogLoadedMsg{catalog: catalog, err: err}
	}
}

func (m Model) updateLoadFailure(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(press, controls.retry) {
		m.loadState, m.screen = loading, loadingScreen
		return m, m.discoveryCommand()
	}
	if key.Matches(press, controls.back) {
		m.screen = overviewScreen
	}
	return m, nil
}

func (m Model) updateConfirmation(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(press, controls.accept) {
		if m.confirmFailed {
			m.confirmFailed = false
			if m.selectedCount() == 0 {
				return m, nil
			}
		}
		return m.startSave()
	}
	if key.Matches(press, controls.decline) {
		m.screen = overviewScreen
	}
	return m, nil
}

func (m Model) startSave() (tea.Model, tea.Cmd) {
	if m.save == nil {
		m.outcome = Outcome{Draft: m.draft, Create: true}
		return m, tea.Quit
	}
	snapshot, err := m.draft.Clone()
	if err != nil {
		m.saveError, m.screen = err, saveFailureScreen
		return m, nil
	}
	m.saveError, m.screen = nil, savingScreen
	save := m.save
	attemptContext, cancel := context.WithCancel(m.context)
	m.saveCancel = cancel
	return m, func() tea.Msg {
		path, err := save(attemptContext, snapshot)
		return saveCompletedMsg{draft: snapshot, path: path, err: err}
	}
}

func (m Model) updateSaveFailure(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(press, controls.retry) {
		return m.startSave()
	}
	if key.Matches(press, controls.cancel) || press.String() == "c" {
		return m.beginCancellation()
	}
	return m, nil
}

func (m Model) beginCancellation() (tea.Model, tea.Cmd) {
	if m.initialValid && m.draft.Equal(m.initialDraft) {
		m.outcome = Outcome{Draft: m.draft, Cancelled: true}
		return m, tea.Quit
	}
	m.returnScreen, m.screen = m.screen, discardScreen
	return m, nil
}

func (m Model) updateDiscard(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(press, controls.accept) {
		m.outcome = Outcome{Draft: m.draft, Cancelled: true}
		return m, tea.Quit
	}
	if key.Matches(press, controls.decline) {
		m.screen = m.returnScreen
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
	program := tea.NewProgram(model.WithContext(ctx), tea.WithContext(ctx), tea.WithInput(input), tea.WithOutput(output))
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
	case loadingScreen:
		content.WriteString("Loading Skills...")
	case loadFailureScreen:
		content.WriteString("Skills failed to load.\n\nR/Enter/Space retry  Esc back")
	case savingScreen:
		content.WriteString("Saving Profile...")
	case cancellingSaveScreen:
		content.WriteString("Cancelling save...")
	case saveFailureScreen:
		content.WriteString("Profile could not be saved: " + safe(m.saveError.Error()) + "\n\nR/Enter retry  Esc cancel")
	case discardScreen:
		content.WriteString("Discard changes?\n\nNo Profile will be created.\n\nY/Enter discard  N/Esc keep editing")
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

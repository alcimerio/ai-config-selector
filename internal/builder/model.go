// Package builder implements the interactive Profile Builder boundary.
package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// MinimumWidth and MinimumHeight define the smallest supported builder layout.
const (
	MinimumWidth  = 64
	MinimumHeight = 18
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
	name                string
	draft               category.Draft
	initialDraft        category.Draft
	initialValid        bool
	editors             []editorSlot
	activeCategory      int
	context             context.Context
	save                SaveFunc
	saveCancel          context.CancelFunc
	confirmFailed       bool
	screen              screen
	returnScreen        screen
	overviewCursor      int
	width               int
	height              int
	sizeKnown           bool
	saveError           error
	outcome             Outcome
	terminalError       error
	runtimeSaves        *saveRuntime
	mutation            *MutationOptions
	prepared            PreparedMutation
	previewDraft        category.Draft
	previewOffset       int
	warningAcknowledged bool
	confirmInput        string
}

type loadState int

const (
	unloaded loadState = iota
	loading
	loaded
	loadFailed
)

type discoveryCompletedMsg struct {
	categoryID string
	discovered any
	err        error
}

type saveCompletedMsg struct {
	draft category.Draft
	path  string
	err   error
}

type screen int

const (
	overviewScreen screen = iota
	categoryScreen
	confirmScreen
	loadingScreen
	loadFailureScreen
	savingScreen
	cancellingSaveScreen
	saveFailureScreen
	discardScreen
	mutationPreviewScreen
	reloadScreen
)

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

// NewModel constructs the root model around a validated visual editor Registry.
func NewModel(name string, draft category.Draft, registry *EditorRegistry) (Model, error) {
	editors, registryErr := registry.newSlots(draft)
	if registryErr != nil {
		return Model{}, registryErr
	}
	initial, err := draft.Clone()
	initialValid := err == nil
	if err != nil {
		initial = draft
	}
	return Model{name: name, draft: draft, initialDraft: initial, initialValid: initialValid, editors: editors, screen: overviewScreen, context: context.Background()}, nil
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
	case discoveryCompletedMsg:
		index := m.editorIndex(message.categoryID)
		if index < 0 || m.editors[index].loadState != loading {
			return m, nil
		}
		if message.err != nil {
			m.editors[index].loadState, m.editors[index].loadError = loadFailed, message.err
			if editor, ok := m.editors[index].editor.(interface{ DiscoveryFailed() Editor }); ok {
				m.editors[index].editor = editor.DiscoveryFailed()
			}
			if index == m.activeCategory {
				m.screen = loadFailureScreen
			}
			return m, nil
		}
		editor, err := m.editors[index].registration.loaded(m.editors[index].editor, message.discovered)
		if err != nil {
			m.editors[index].loadState, m.editors[index].loadError = loadFailed, err
			if index == m.activeCategory {
				m.screen = loadFailureScreen
			}
			return m, nil
		}
		m.editors[index].editor, m.editors[index].loadState, m.editors[index].loadError = editor, loaded, nil
		if index == m.activeCategory {
			m.screen = categoryScreen
		}
		return m, nil
	case saveCompletedMsg:
		if m.screen != savingScreen && m.screen != cancellingSaveScreen {
			return m, nil
		}
		m.saveCancel = nil
		var transactionError *profilerepo.OutcomeError
		if errors.As(message.err, &transactionError) && (transactionError.Outcome.State != profilerepo.NotCommitted || transactionError.Outcome.RecoveryRequired) {
			// Never offer blind retry or report cancellation after publication
			// may have happened, or while cleanup still needs recovery.
			m.terminalError = message.err
			return m, tea.Quit
		}
		if m.screen == cancellingSaveScreen && errors.Is(message.err, context.Canceled) {
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
		m.sizeKnown = true
		return m, nil
	case tea.KeyPressMsg:
		if (message.String() == "ctrl+c" || message.String() == "ctrl+d") && m.screen == savingScreen {
			m.saveCancel()
			m.screen = cancellingSaveScreen
			return m, nil
		}
		if (message.String() == "ctrl+c" || message.String() == "ctrl+d") && m.screen != cancellingSaveScreen && m.screen != discardScreen {
			return m.beginCancellation()
		}
		if m.tooSmall() {
			return m, nil
		}
		switch m.screen {
		case overviewScreen:
			return m.updateOverview(message)
		case categoryScreen:
			return m.updateEditor(message)
		case confirmScreen:
			return m.updateConfirmation(message)
		case loadFailureScreen:
			return m.updateLoadFailure(message)
		case saveFailureScreen:
			return m.updateSaveFailure(message)
		case discardScreen:
			return m.updateDiscard(message)
		case mutationPreviewScreen:
			return m.updateMutationPreview(message)
		case reloadScreen:
			return m.updateReload(message)
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
			if m.mutation != nil {
				prepared, err := m.prepareMutation()
				if err != nil {
					m.saveError, m.screen = err, saveFailureScreen
					return m, nil
				}
				return prepared, nil
			}
			if len(m.failedCategoryNames()) != 0 {
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
			m.activeCategory = m.overviewCursor
			slot := &m.editors[m.activeCategory]
			slot.editor = slot.editor.WithDraft(m.draft)
			if slot.loadState == unloaded || slot.loadState == loadFailed {
				slot.loadState, m.screen = loading, loadingScreen
				return m, m.discoveryCommand(m.activeCategory)
			}
			if slot.loadState == loaded {
				m.screen = categoryScreen
			}
		}
	case key.Matches(press, controls.cancel):
		return m.beginCancellation()
	}
	return m, nil
}

func (m Model) updateEditor(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	slot := &m.editors[m.activeCategory]
	if m.mutation != nil && slot.editor.ListFocused() && press.String() == "r" {
		slot.loadState, m.screen = loading, loadingScreen
		return m, m.discoveryCommand(m.activeCategory)
	}
	if slot.editor.ListFocused() && key.Matches(press, controls.back) {
		m.draft, m.screen = slot.editor.Draft(), overviewScreen
		return m, nil
	}
	updated, command := slot.editor.Update(press)
	editor, ok := updated.(Editor)
	if !ok {
		return m, nil
	}
	slot.editor, m.draft = editor, editor.Draft()
	for index := range m.editors {
		if index != m.activeCategory {
			m.editors[index].editor = m.editors[index].editor.WithDraft(m.draft)
		}
	}
	return m, command
}

func (m Model) discoveryCommand(index int) tea.Cmd {
	registration, ctx := m.editors[index].registration, m.context
	return func() tea.Msg {
		discovered, err := registration.discover(ctx)
		return discoveryCompletedMsg{categoryID: registration.id, discovered: discovered, err: err}
	}
}

func (m Model) updateLoadFailure(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if press.String() == "e" {
		m.screen = categoryScreen
		return m, nil
	}
	if key.Matches(press, controls.retry) {
		m.editors[m.activeCategory].loadState, m.screen = loading, loadingScreen
		return m, m.discoveryCommand(m.activeCategory)
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
				m.screen = confirmScreen
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
		defer cancel()
		if m.runtimeSaves != nil {
			return m.runtimeSaves.execute(attemptContext, snapshot, save)
		}
		path, err := save(attemptContext, snapshot)
		return saveCompletedMsg{draft: snapshot, path: path, err: err}
	}
}

func (m Model) updateSaveFailure(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.mutation != nil {
		return m.mutationSaveFailure(press)
	}
	if key.Matches(press, controls.retry) {
		return m.startSave()
	}
	if key.Matches(press, controls.cancel) {
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

type programRuntime interface {
	Run() (tea.Model, error)
}

func finishRuntime(runtime programRuntime) (Outcome, error) {
	completed, err := runtime.Run()
	if err != nil {
		return Outcome{}, err
	}
	final, ok := completed.(Model)
	if !ok {
		return Outcome{}, fmt.Errorf("Profile Builder returned %T, not its root model", completed)
	}
	return final.Outcome(), final.terminalError
}

// Run starts the sole Bubble Tea program for a Profile Builder session.
func Run(ctx context.Context, model Model, input io.Reader, output io.Writer) (Outcome, error) {
	tracker := &saveRuntime{}
	model.runtimeSaves = tracker
	program := tea.NewProgram(
		model.WithContext(ctx),
		tea.WithContext(ctx),
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithEnvironment(os.Environ()),
	)
	outcome, err := finishRuntime(program)
	settled := tracker.settle()
	if err != nil && settled != nil {
		if settled.err == nil {
			return Outcome{Draft: settled.draft, Path: settled.path, Create: true}, nil
		}
		return Outcome{}, errors.Join(err, settled.err)
	}
	return outcome, err
}

// View renders the single alternate-screen builder UI.
func (m Model) View() tea.View {
	if m.tooSmall() {
		footer := "\n\nResize the terminal to continue."
		switch m.screen {
		case savingScreen:
			footer = "\n\nCtrl+C cancel save"
		case discardScreen, cancellingSaveScreen:
		default:
			footer = "\n\nCtrl+C cancel"
		}
		content := fmt.Sprintf(
			"Terminal too small\n\nResize to at least %d columns by %d rows.\nCurrent size: %d by %d.\n\nYour Profile Draft is preserved.%s",
			MinimumWidth, MinimumHeight, m.width, m.height, footer,
		)
		view := tea.NewView(content)
		view.AltScreen = true
		return view
	}
	var content strings.Builder
	switch m.screen {
	case overviewScreen:
		label := "Create"
		if m.mutation != nil {
			label = m.mutation.Label
		}
		content.WriteString(label + " Profile \"")
		content.WriteString(m.name)
		content.WriteString("\"\n\n")
		categories := m.categories()
		rows := make([]string, 0, len(categories)+2)
		for _, summary := range categories {
			rows = append(rows, categoryName(summary.ID)+"                         "+plural(summary.Count, "selected"))
		}
		action := "Create Profile"
		if m.mutation != nil {
			action = "Preview " + m.mutation.Label
		}
		rows = append(rows, action, "Cancel")
		for index, row := range rows {
			marker := "  "
			if index == m.overviewCursor {
				marker = "> "
			}
			content.WriteString(marker + row + "\n")
		}
		content.WriteString("\nUp/Down navigate  Space/Enter/Right open\nEsc cancel  Ctrl+C cancel")
	case categoryScreen:
		content.WriteString(m.editors[m.activeCategory].editor.View().Content)
		if m.mutation != nil {
			content.WriteString("\nR refresh sources (list focus)")
		}
	case confirmScreen:
		if m.confirmFailed {
			content.WriteString("Confirm: These categories failed to load: " + strings.Join(m.failedCategoryNames(), ", ") + ". Create Profile anyway?\n\nY/Enter create  N/Esc/Left return\nCtrl+C cancel")
		} else {
			content.WriteString("Confirm: Create an empty Profile?\n\nThis Profile will not select any capabilities.\n\nY/Enter create  N/Esc/Left return\nCtrl+C cancel")
		}
	case loadingScreen:
		content.WriteString("Loading " + categoryName(m.editors[m.activeCategory].registration.id) + "...\n\nCtrl+C cancel")
	case loadFailureScreen:
		content.WriteString("Error: " + categoryName(m.editors[m.activeCategory].registration.id) + " failed to load.\n\nR/Enter/Space retry  E edit saved selections  Left/Esc back\nCtrl+C cancel")
	case savingScreen:
		content.WriteString("Saving Profile...\n\nCtrl+C cancel save")
	case cancellingSaveScreen:
		content.WriteString("Cancelling save...\n\nPlease wait")
	case mutationPreviewScreen:
		content.WriteString(m.mutationPreviewView())
	case reloadScreen:
		content.WriteString("Reload stored Profile? This discards your preserved draft.\n\nY reload and build a new preview  N/Esc keep draft")
	case saveFailureScreen:
		if m.mutation != nil {
			text := "Save failed. Your draft is preserved. " + safe(m.saveError.Error())
			if errors.Is(m.saveError, profilerepo.ErrConflict) {
				text = "Storage changed. Your draft and newer stored data are preserved.\nNo force retry is permitted. Reload explicitly to create a new preview."
			} else {
				text += "\nR/Enter new preview"
			}
			content.WriteString(text + "\n\nL request reload  Esc cancel  Ctrl+C cancel")
			break
		}
		content.WriteString("Error: Profile could not be saved: " + safe(m.saveError.Error()) + "\n\nR/Enter/Space retry  Esc cancel\nCtrl+C cancel")
	case discardScreen:
		content.WriteString("Confirm: Discard changes?\n\nNo Profile mutation will be published.\n\nY/Enter discard  N/Esc/Left keep editing")
	}
	rendered := content.String()
	if m.sizeKnown {
		rendered = fitWidth(rendered, m.width)
	}
	view := tea.NewView(rendered)
	view.AltScreen = true
	return view
}

func (m Model) tooSmall() bool {
	return m.sizeKnown && (m.width < MinimumWidth || m.height < MinimumHeight)
}

func fitWidth(content string, width int) string {
	lines := strings.Split(content, "\n")
	for index, line := range lines {
		lines[index] = ansi.Truncate(line, width, "…")
	}
	return strings.Join(lines, "\n")
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

func (m Model) editorIndex(id string) int {
	for index := range m.editors {
		if m.editors[index].registration.id == id {
			return index
		}
	}
	return -1
}

func (m Model) failedCategoryNames() []string {
	failed := make([]string, 0)
	for _, slot := range m.editors {
		if slot.loadState == loadFailed {
			failed = append(failed, categoryName(slot.registration.id))
		}
	}
	return failed
}

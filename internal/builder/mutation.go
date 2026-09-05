package builder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/charmbracelet/x/ansi"
)

// PreparedMutation binds displayed representation to one immutable commit.
// Prepare must not write; Save must use the same desired bytes and revisions.
type PreparedMutation struct {
	Text    string
	Save    SaveFunc
	Warning bool
}

// MutationOptions reuses builder navigation, selection and terminal ownership.
// Reload explicitly discards the draft only after a second confirmation.
type MutationOptions struct {
	Label        string
	Prepare      func(category.Draft) (PreparedMutation, error)
	Reload       func(context.Context) (category.Draft, error)
	Compact      bool
	Confirmation string
}

func (m Model) WithMutation(options MutationOptions) (Model, error) {
	if options.Prepare == nil || options.Label == "" {
		return m, errors.New("incomplete Profile mutation editor")
	}
	m.mutation = &options
	if options.Compact {
		return m.prepareMutation()
	}
	return m, nil
}

func (m Model) prepareMutation() (Model, error) {
	snapshot, err := m.draft.Clone()
	if err != nil {
		return m, err
	}
	prepared, err := m.mutation.Prepare(snapshot)
	if err != nil {
		return m, err
	}
	if prepared.Save == nil {
		return m, errors.New("Profile preview has no commit")
	}
	var unresolved []string
	for _, slot := range m.editors {
		if editor, ok := slot.editor.WithDraft(snapshot).(interface{ Unresolved() []string }); ok {
			unresolved = append(unresolved, editor.Unresolved()...)
		}
	}
	if len(unresolved) != 0 {
		prepared.Warning = true
		prepared.Text += "\nRetained unresolved selections (source availability is separate from structural validity):\n  " + strings.Join(unresolved, "\n  ") + "\n"
	}
	m.prepared, m.previewDraft = prepared, snapshot
	m.previewOffset, m.warningAcknowledged, m.confirmInput = 0, false, ""
	m.screen = mutationPreviewScreen
	return m, nil
}

func (m Model) updateMutationPreview(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	lines, height := m.previewLines(), m.previewHeight()
	switch press.String() {
	case "up":
		if m.previewOffset > 0 {
			m.previewOffset--
		}
		return m, nil
	case "down":
		if m.previewOffset < len(lines)-height {
			m.previewOffset++
		}
		return m, nil
	case "pgdown":
		m.previewOffset = min(m.previewOffset+height, max(0, len(lines)-height))
		return m, nil
	case "pgup":
		m.previewOffset = max(0, m.previewOffset-height)
		return m, nil
	case "end":
		m.previewOffset = max(0, len(lines)-height)
		return m, nil
	case "home":
		m.previewOffset = 0
		return m, nil
	case "esc", "left":
		m.prepared = PreparedMutation{}
		if m.mutation.Compact {
			return m.beginCancellation()
		}
		m.screen = overviewScreen
		return m, nil
	}
	// Every page must be reachable; commit requires reaching the final page.
	if m.previewOffset+height < len(lines) {
		return m, nil
	}
	if m.prepared.Warning && !m.warningAcknowledged {
		if press.String() == "a" {
			m.warningAcknowledged = true
		}
		return m, nil
	}
	if m.mutation.Confirmation != "" {
		switch press.String() {
		case "backspace":
			if len(m.confirmInput) > 0 {
				m.confirmInput = m.confirmInput[:len(m.confirmInput)-1]
			}
		case "enter":
			if m.confirmInput != m.mutation.Confirmation {
				m.confirmInput = ""
				return m, nil
			}
			return m.commitPrepared()
		default:
			text := press.Key().Text
			if len(m.confirmInput)+len(text) <= 64 && !strings.ContainsFunc(text, unicode.IsControl) {
				m.confirmInput += text
			}
		}
		return m, nil
	}
	if press.String() == "y" || press.String() == "enter" {
		return m.commitPrepared()
	}
	return m, nil
}

func (m Model) commitPrepared() (tea.Model, tea.Cmd) {
	m.save = m.prepared.Save
	// The prepared closure owns bytes and revisions. Clone the frozen draft again
	// for the outcome only; it cannot reconstruct the commit from mutable UI state.
	m.draft = m.previewDraft
	return m.startSave()
}

func (m Model) previewHeight() int {
	if m.sizeKnown {
		return max(1, m.height-8)
	}
	return 16
}
func (m Model) previewLines() []string {
	width := 80
	if m.sizeKnown {
		width = m.width
	}
	return strings.Split(ansi.Hardwrap(m.prepared.Text, width, true), "\n")
}
func (m Model) mutationPreviewView() string {
	lines, height := m.previewLines(), m.previewHeight()
	offset := min(m.previewOffset, max(0, len(lines)-height))
	footer := "Y/Enter commit  Esc return  Ctrl+C cancel"
	if offset+height < len(lines) {
		footer = "Read remaining preview before confirmation"
	} else if m.prepared.Warning && !m.warningAcknowledged {
		footer = "A acknowledge unresolved selections warning before confirmation"
	} else if m.mutation.Confirmation != "" {
		footer = "Type exact name " + m.mutation.Confirmation + ", then Enter: " + safe(m.confirmInput)
	}
	return fmt.Sprintf("%s Profile %q — preview\n\n%s\n\nLines %d-%d/%d  Up/Down/PgUp/PgDn/End scroll\n%s\nEsc return  Ctrl+C cancel", m.mutation.Label, m.name, strings.Join(lines[offset:min(offset+height, len(lines))], "\n"), offset+1, min(offset+height, len(lines)), len(lines), footer)
}

func (m Model) mutationSaveFailure(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if press.String() == "esc" {
		return m.beginCancellation()
	}
	if press.String() == "l" && m.mutation.Reload != nil {
		m.screen = reloadScreen
		return m, nil
	}
	if !errors.Is(m.saveError, profilerepo.ErrConflict) && (press.String() == "r" || press.String() == "enter") {
		prepared, err := m.prepareMutation()
		if err != nil {
			m.saveError = err
			return m, nil
		}
		return prepared, nil
	}
	return m, nil
}

func (m Model) updateReload(press tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch press.String() {
	case "n", "esc":
		m.screen = saveFailureScreen
	case "y":
		draft, err := m.mutation.Reload(m.context)
		if err != nil {
			m.saveError, m.screen = err, saveFailureScreen
			return m, nil
		}
		m.draft = draft
		m.initialDraft, err = draft.Clone()
		m.initialValid = err == nil
		for index := range m.editors {
			m.editors[index].editor = m.editors[index].registration.new(draft)
			m.editors[index].loadState = unloaded
		}
		m.saveError, m.screen, m.prepared = nil, overviewScreen, PreparedMutation{}
		if m.mutation.Compact {
			prepared, err := m.prepareMutation()
			if err != nil {
				m.saveError, m.screen = err, saveFailureScreen
				return m, nil
			}
			return prepared, nil
		}
	}
	return m, nil
}

package builder

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
)

// CreationOptions selects overlays independently from common capabilities.
// Authentication remains an explicit launch-time reference.
type CreationOptions struct {
	Devin, Codex bool
	Development  bool
}
type CreationSaveFunc func(context.Context, category.Draft, CreationOptions) (string, error)

// WithCreation asks for explicit target and workspace choices before editing.
func (m Model) WithCreation(save CreationSaveFunc, preset func(*category.Draft, bool) error) Model {
	m.creation = &CreationOptions{}
	m.creationSave, m.creationPreset, m.screen = save, preset, creationScreen
	return m
}
func (m Model) updateCreation(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.tooSmall() && key.String() != "ctrl+c" && key.String() != "ctrl+d" && key.String() != "esc" {
		return m, nil
	}
	switch key.String() {
	case "ctrl+c", "ctrl+d", "esc":
		m.outcome.Cancelled = true
		return m, tea.Quit
	case "up":
		if m.creationCursor > 0 {
			m.creationCursor--
		}
	case "down":
		if m.creationCursor < 3 {
			m.creationCursor++
		}
	case "space", "enter":
		options := *m.creation
		switch m.creationCursor {
		case 0:
			options.Devin = !options.Devin
		case 1:
			options.Codex = !options.Codex
		case 2:
			options.Development = !options.Development
		case 3:
			if err := m.creationPreset(&m.draft, options.Development); err != nil {
				m.terminalError = err
				return m, tea.Quit
			}
			m.initialDraft, _ = m.draft.Clone()
			m.save = func(ctx context.Context, draft category.Draft) (string, error) {
				return m.creationSave(ctx, draft, options)
			}
			m.screen = overviewScreen
		}
		m.creation = &options
	}
	return m, nil
}
func (m Model) creationSummary() string {
	targets := []string{}
	if m.creation.Devin {
		targets = append(targets, "Devin")
	}
	if m.creation.Codex {
		targets = append(targets, "Codex")
	}
	if len(targets) == 0 {
		targets = append(targets, "common only")
	}
	return "Targets: " + strings.Join(targets, ", ") + ". Workspace access can be changed in Workspace."
}
func (m Model) creationView() string {
	mark := func(selected bool) string {
		if selected {
			return "[x]"
		}
		return "[ ]"
	}
	preset := "Review (workspace read-only)"
	if m.creation.Development {
		preset = "Development (workspace read-write)"
	}
	rows := []string{mark(m.creation.Devin) + " Devin overlay", mark(m.creation.Codex) + " Codex overlay", "Preset: " + preset, "Continue to common categories"}
	var text strings.Builder
	fmt.Fprintf(&text, "Create Profile %q\n\nChoose targets and workspace access\n\n", m.name)
	for i, row := range rows {
		marker := "  "
		if i == m.creationCursor {
			marker = "> "
		}
		text.WriteString(marker + row + "\n")
	}
	text.WriteString("\nNeither overlay is required for sandbox or run.\nBoth overlays share the same common capabilities.\nNo login or executable is required.\nCodex authentication uses --auth at launch.\n\nUp/Down navigate  Space/Enter select\nEsc/Ctrl+C cancel")
	return text.String()
}

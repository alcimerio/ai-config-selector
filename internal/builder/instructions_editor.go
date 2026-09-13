package builder

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
)

type instructionEditor struct {
	draft      category.Draft
	binding    commonprofile.InstructionsBinding
	catalog    []instructions.Bundle
	cursor     int
	discovered bool
}

func RegisterInstructionsEditor(binding commonprofile.InstructionsBinding, discover func(context.Context) ([]instructions.Bundle, error)) (EditorRegistration, error) {
	return RegisterEditor(EditorDefinition[[]instructions.Bundle, instructionEditor]{ID: binding.ID(), Category: binding.Registration(), New: func(d category.Draft) instructionEditor { return instructionEditor{draft: d, binding: binding} }, Discover: discover, Loaded: func(e instructionEditor, c []instructions.Bundle) (instructionEditor, error) {
		e.catalog = append([]instructions.Bundle(nil), c...)
		e.discovered = true
		return e, nil
	}})
}
func (m instructionEditor) Draft() category.Draft             { return m.draft }
func (m instructionEditor) WithDraft(d category.Draft) Editor { m.draft = d; return m }
func (m instructionEditor) Init() tea.Cmd                     { return nil }
func (m instructionEditor) ListFocused() bool                 { return true }
func (m instructionEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	selected, _ := category.Selection(m.draft, m.binding)
	switch press.String() {
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		if m.cursor+1 < len(m.rows(selected)) {
			m.cursor++
		}
	case "space", "enter":
		rows := m.rows(selected)
		if m.cursor < len(rows) {
			ref := rows[m.cursor]
			found := -1
			for i, v := range selected {
				if v == ref {
					found = i
					break
				}
			}
			if found >= 0 {
				selected = append(selected[:found], selected[found+1:]...)
			} else if len(selected) < instructions.MaxEntries {
				selected = append(selected, ref)
			}
			_ = category.SetSelection(&m.draft, m.binding, selected)
		}
	}
	return m, nil
}
func (m instructionEditor) View() tea.View {
	selected, _ := category.Selection(m.draft, m.binding)
	rows := m.rows(selected)
	var b strings.Builder
	fmt.Fprintf(&b, "Instructions                 %d selected\n\n", len(selected))
	for i, ref := range rows {
		mark := "[ ]"
		for _, s := range selected {
			if s == ref {
				mark = "[x]"
				break
			}
		}
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}
		label := ref.RelativePath
		found := false
		for _, item := range m.catalog {
			if item.Reference == ref {
				found = true
				break
			}
		}
		if !found {
			label += " (missing)"
		}
		fmt.Fprintf(&b, "%s%s %s\n", cursor, mark, label)
	}
	if len(rows) == 0 {
		b.WriteString("  No instruction bundles discovered. Add UTF-8 .md files under ~/.acs/instructions.\n")
	}
	b.WriteString("\nUp/Down navigate  Space/Enter toggle  Left/Esc back  Ctrl+C cancel")
	return tea.NewView(b.String())
}
func (m instructionEditor) Unresolved() []string {
	selected, _ := category.Selection(m.draft, m.binding)
	var warnings []string
	for _, ref := range selected {
		status := "available"
		if !m.discovered {
			status = "unavailable/unchecked"
		} else {
			count := 0
			for _, item := range m.catalog {
				if item.Reference == ref {
					count++
				}
			}
			switch count {
			case 0:
				status = "missing"
			case 1:
				continue
			default:
				status = "ambiguous"
			}
		}
		warnings = append(warnings, safe(ref.Source)+":"+safe(ref.RelativePath)+" ("+status+")")
	}
	return warnings
}
func (m instructionEditor) DiscoveryFailed() Editor {
	m.discovered = false
	return m
}
func DiscoverInstructionCatalog(home string) ([]instructions.Bundle, error) {
	return instructions.Discover(home)
}

func (m instructionEditor) rows(selected []instructions.Reference) []instructions.Reference {
	rows := make([]instructions.Reference, 0, len(m.catalog)+len(selected))
	seen := map[instructions.Reference]bool{}
	for _, v := range m.catalog {
		rows = append(rows, v.Reference)
		seen[v.Reference] = true
	}
	for _, v := range selected {
		if !seen[v] {
			rows = append(rows, v)
			seen[v] = true
		}
	}
	return rows
}

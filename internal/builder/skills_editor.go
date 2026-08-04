package builder

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const skillsViewportRows = 8

// NewSkillsEditor constructs the Skills child model. It never starts a
// Bubble Tea program; the root model remains the runtime owner.
func NewSkillsEditor[C launch.Contribution](draft category.Draft, binding category.Binding[[]skills.SkillReference, []skills.SkillBundle, C], catalog ...[]skills.SkillBundle) skillsEditor {
	var discovered []skills.SkillBundle
	if len(catalog) != 0 {
		discovered = catalog[0]
	}
	ordered := append([]skills.SkillBundle(nil), discovered...)
	sort.SliceStable(ordered, func(left, right int) bool { return catalogOrder(ordered[left], ordered[right]) })
	return skillsEditor{
		draft: draft,
		selection: func(draft category.Draft) ([]skills.SkillReference, error) {
			return category.Selection(draft, binding)
		},
		setSelection: func(draft *category.Draft, selection []skills.SkillReference) error {
			return category.SetSelection(draft, binding, selection)
		},
		id: binding.ID(), catalog: ordered,
	}
}

func (m skillsEditor) WithCatalog(catalog []skills.SkillBundle) skillsEditor {
	ordered := append([]skills.SkillBundle(nil), catalog...)
	sort.SliceStable(ordered, func(left, right int) bool { return catalogOrder(ordered[left], ordered[right]) })
	m.catalog = ordered
	m.clamp()
	return m
}

type skillsEditor struct {
	draft        category.Draft
	selection    func(category.Draft) ([]skills.SkillReference, error)
	setSelection func(*category.Draft, []skills.SkillReference) error
	id           string
	catalog      []skills.SkillBundle
	query        string
	queryCursor  int
	searchFocus  bool
	cursor       int
	scrollOffset int
}

func (m skillsEditor) ID() string            { return m.id }
func (m skillsEditor) Draft() category.Draft { return m.draft }
func (m skillsEditor) Init() tea.Cmd         { return nil }
func (m skillsEditor) ListFocused() bool     { return !m.searchFocus }

func (m skillsEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	press, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	if m.searchFocus {
		m.updateSearch(press)
		m.clamp()
		return m, nil
	}
	switch {
	case press.String() == "/":
		m.searchFocus = true
		m.queryCursor = len([]rune(m.query))
	case key.Matches(press, controls.up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(press, controls.down):
		if m.cursor < len(m.visible())-1 {
			m.cursor++
		}
	case key.Matches(press, controls.toggle):
		visible := m.visible()
		if len(visible) > 0 {
			m.toggle(m.catalog[visible[m.cursor]].Reference)
		}
	}
	m.clamp()
	return m, nil
}

func (m *skillsEditor) updateSearch(press tea.KeyPressMsg) {
	switch press.String() {
	case "esc":
		m.query = ""
		m.queryCursor = 0
		m.searchFocus = false
	case "left":
		if m.queryCursor > 0 {
			m.queryCursor--
		}
	case "right":
		if m.queryCursor < len([]rune(m.query)) {
			m.queryCursor++
		}
	case "backspace":
		if m.queryCursor > 0 {
			m.query = replaceRunes(m.query, m.queryCursor-1, m.queryCursor, "")
			m.queryCursor--
		}
	default:
		text := press.Key().Text
		if text != "" && !strings.ContainsFunc(text, unicode.IsControl) {
			m.query = replaceRunes(m.query, m.queryCursor, m.queryCursor, text)
			m.queryCursor += len([]rune(text))
		}
	}
}

func (m *skillsEditor) clamp() {
	visible := m.visible()
	if len(visible) == 0 {
		m.cursor, m.scrollOffset = 0, 0
		return
	}
	if m.cursor >= len(visible) {
		m.cursor = len(visible) - 1
	}
	if m.scrollOffset > m.cursor {
		m.scrollOffset = m.cursor
	}
	if m.cursor >= m.scrollOffset+skillsViewportRows {
		m.scrollOffset = m.cursor - skillsViewportRows + 1
	}
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
	selected, _ := m.selection(m.draft)
	content.WriteString("Skills                         " + strconv.Itoa(len(selected)) + " selected\n")
	if m.searchFocus {
		content.WriteString("Search: " + safe(m.query) + "\n")
	} else if m.query != "" {
		content.WriteString("Search: " + safe(m.query) + "\n")
	}
	content.WriteString("\n")
	visible := m.visible()
	end := min(m.scrollOffset+skillsViewportRows, len(visible))
	for position := m.scrollOffset; position < end; position++ {
		bundle := m.catalog[visible[position]]
		marker, selected := "  ", "[ ]"
		if position == m.cursor {
			marker = "> "
		}
		if m.isSelected(bundle.Reference) {
			selected = "[x]"
		}
		content.WriteString(marker + selected + " " + safe(bundle.DisplayName) + " [" + safe(string(bundle.Reference.Source)) + "]\n")
	}
	if len(visible) == 0 {
		content.WriteString("  (no matching Skills)\n")
	}
	if len(visible) > 0 {
		bundle := m.catalog[visible[m.cursor]]
		content.WriteString("\nSource: " + safe(string(bundle.Reference.Source)) + "\nPath: " + safe(bundle.BundlePath) + "\n")
	}
	if m.searchFocus {
		content.WriteString("\nType to search  Left/Right move cursor\nBackspace delete  Esc clear search  Ctrl+C cancel")
	} else {
		content.WriteString("\nUp/Down navigate  Space/Enter toggle  / search\nLeft/Esc back  Ctrl+C cancel")
	}
	return tea.NewView(content.String())
}

func (m skillsEditor) visible() []int {
	if m.query == "" {
		visible := make([]int, len(m.catalog))
		for i := range m.catalog {
			visible[i] = i
		}
		return visible
	}
	type match struct{ index, field, score int }
	matches := make([]match, 0)
	for index, bundle := range m.catalog {
		field, score, ok := bundleMatch(bundle, m.query)
		if ok {
			matches = append(matches, match{index, field, score})
		}
	}
	sort.SliceStable(matches, func(left, right int) bool {
		if matches[left].field != matches[right].field {
			return matches[left].field < matches[right].field
		}
		if matches[left].score != matches[right].score {
			return matches[left].score < matches[right].score
		}
		return catalogOrder(m.catalog[matches[left].index], m.catalog[matches[right].index])
	})
	visible := make([]int, len(matches))
	for i, match := range matches {
		visible[i] = match.index
	}
	return visible
}

func bundleMatch(bundle skills.SkillBundle, query string) (int, int, bool) {
	for field, value := range []string{bundle.DisplayName, string(bundle.Reference.Source), bundle.BundlePath} {
		if score, ok := fuzzyScore(value, query); ok {
			return field, score, true
		}
	}
	return 0, 0, false
}

func fuzzyScore(value, query string) (int, bool) {
	valueRunes, queryRunes := []rune(strings.ToLower(value)), []rune(strings.ToLower(query))
	position, score := 0, 0
	for _, character := range queryRunes {
		next := -1
		for index := position; index < len(valueRunes); index++ {
			if valueRunes[index] == character {
				next = index
				break
			}
		}
		if next < 0 {
			return 0, false
		}
		score += next - position
		position = next + 1
	}
	return score, true
}

func catalogOrder(left, right skills.SkillBundle) bool {
	for _, pair := range [][2]string{{left.DisplayName, right.DisplayName}, {string(left.Reference.Source), string(right.Reference.Source)}, {left.Reference.RelativePath, right.Reference.RelativePath}} {
		if strings.EqualFold(pair[0], pair[1]) {
			continue
		}
		return strings.ToLower(pair[0]) < strings.ToLower(pair[1])
	}
	if left.Reference.Source != right.Reference.Source {
		return left.Reference.Source < right.Reference.Source
	}
	return left.Reference.RelativePath < right.Reference.RelativePath
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
func replaceRunes(value string, start, end int, replacement string) string {
	runes := []rune(value)
	return string(append(append(runes[:start:start], []rune(replacement)...), runes[end:]...))
}
func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

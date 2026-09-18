package acceptance_test

import (
	"errors"
	"fmt"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/parser"
	"github.com/charmbracelet/x/vt"
	"image/color"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// devinScreen uses a pinned maintained emulator for cursor, erase, style and
// screen state. It never searches historical output for input readiness.
type devinScreen struct {
	framing           *ansi.Parser
	mu                sync.Mutex
	terminal          *vt.Emulator
	visible, updating bool
	bracketed         bool
	total             int
	failure           error
	replies           [][]byte
	queryCount        map[byte]int
}

func newDevinScreen() *devinScreen {
	s := &devinScreen{framing: ansi.NewParser(), terminal: vt.NewEmulator(120, 40), visible: true, queryCount: map[byte]int{}}
	_ = s.terminal.InputPipe().(io.Closer).Close()
	s.terminal.SetCallbacks(vt.Callbacks{CursorVisibility: func(v bool) { s.visible = v }, EnableMode: func(m ansi.Mode) {
		if m == ansi.ModeBracketedPaste {
			s.bracketed = true
		}
		if m == ansi.ModeSynchronizedOutput {
			s.updating = true
		}
	}, DisableMode: func(m ansi.Mode) {
		if m == ansi.ModeBracketedPaste {
			s.bracketed = false
		}
		if m == ansi.ModeSynchronizedOutput {
			s.updating = false
		}
	}})
	// Only query forms actually observed in pinned Devin are answered. Override
	// these handlers so upstream input-pipe responses never bypass our bounds.
	s.terminal.RegisterCsiHandler(int('n'), func(p ansi.Params) bool {
		n, _, _ := p.Param(0, 0)
		if len(p) != 1 || p[0].HasMore() || n != 6 {
			s.failure = errors.New("unobserved DSR query")
			return true
		}
		position := s.terminal.CursorPosition()
		s.reply('n', []byte(fmt.Sprintf("\x1b[%d;%dR", position.Y+1, position.X+1)))
		return true
	})
	s.terminal.RegisterCsiHandler(int('c'), func(p ansi.Params) bool {
		n, _, _ := p.Param(0, 0)
		if len(p) > 1 || (len(p) == 1 && p[0].HasMore()) || n != 0 {
			s.failure = errors.New("unobserved DA query")
			return true
		}
		s.reply('c', []byte("\x1b[?1;2c"))
		return true
	})
	s.terminal.RegisterCsiHandler(ansi.Command('?', 0, 'u'), func(p ansi.Params) bool {
		if len(p) != 0 {
			s.failure = errors.New("unobserved keyboard query parameters")
			return true
		}
		s.reply('u', []byte("\x1b[?0u"))
		return true
	})
	return s
}
func (s *devinScreen) reply(kind byte, b []byte) {
	s.queryCount[kind]++
	if s.queryCount[kind] > 4 {
		s.failure = errors.New("terminal query repeat cap")
		return
	}
	s.replies = append(s.replies, b)
}
func (s *devinScreen) feed(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += len(b)
	if len(b) > 16384 || s.total > 1<<20 {
		s.failure = errors.New("terminal capture cap")
	}
	if s.failure != nil {
		return s.failure
	}
	for _, v := range b {
		s.framing.Advance(v)
	}
	_, e := s.terminal.Write(b)
	if e == nil {
		e = s.failure
	}
	return e
}
func (s *devinScreen) visibleLines() ([]string, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil || s.updating || !s.visible || s.framing.State() != parser.GroundState {
		return nil, 0, false
	}
	lines := make([]string, 40)
	for y := 0; y < 40; y++ {
		var b strings.Builder
		for x := 0; x < 120; x++ {
			c := s.terminal.CellAt(x, y)
			if c == nil || c.Style.Attrs&uv.AttrConceal != 0 || (c.Style.Fg != nil && c.Style.Bg != nil && reflect.DeepEqual(c.Style.Fg, c.Style.Bg)) {
				b.WriteByte(' ')
			} else {
				b.WriteString(c.Content)
			}
		}
		lines[y] = strings.TrimRight(b.String(), " ")
	}
	return lines, s.terminal.CursorPosition().Y, true
}

func TestDevinProtocolVisibleScreenRegression(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		visible     bool
	}{{"visible", "\x1b[?25hCode:Paste the code", true}, {"clear", "\x1b[?25hCode:Paste the code\x1b[2J\x1b[?25l", false}, {"sync", "\x1b[?2026h\x1b[?25hCode:Paste the code", false}, {"osc", "\x1b]0;Code:Paste the code\x07\x1b[?25h", true}, {"conceal", "\x1b[8mCode:Paste the code\x1b[?25h", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDevinScreen()
			for _, b := range []byte(tc.input) {
				if e := s.feed([]byte{b}); e != nil {
					t.Fatal(e)
				}
			}
			lines, _, visible := s.visibleLines()
			if visible != tc.visible {
				t.Fatalf("visible=%v", visible)
			}
			if tc.name != "visible" && strings.Contains(strings.Join(lines, "\n"), "Code:") {
				t.Fatal("hidden/historical text survived")
			}
		})
	}
}

func TestDevinProtocolIncompleteTerminalSequence(t *testing.T) {
	for _, suffix := range []string{"\x1b[?25", "\x1b]0;title", "\xe2\x9d"} {
		s := newDevinScreen()
		if e := s.feed([]byte("prompt" + suffix)); e != nil {
			t.Fatal(e)
		}
		if _, _, ready := s.visibleLines(); ready {
			t.Fatal("incomplete terminal sequence appeared ready")
		}
	}
}

func (s *devinScreen) initialPromptStyles() bool {
	pos := s.terminal.CursorPosition()
	if pos.X != 2 || pos.Y < 1 || pos.Y >= 39 {
		return false
	}
	text := []rune("❭ Ask Devin to build features, fix bugs, or work on your code")
	for x, ch := range text {
		c := s.terminal.CellAt(x, pos.Y)
		if c == nil || c.Content != string(ch) || c.Style.Attrs != 0 || c.Style.Bg != nil {
			return false
		}
		if x < 2 {
			if c.Style.Fg != nil {
				return false
			}
		} else if !reflect.DeepEqual(c.Style.Fg, ansi.IndexedColor(244)) {
			return false
		}
	}
	for _, y := range []int{pos.Y - 1, pos.Y + 1} {
		for x := 0; x < 120; x++ {
			c := s.terminal.CellAt(x, y)
			if c == nil || c.Content != "─" || c.Style.Attrs != 0 || c.Style.Bg != nil || !reflect.DeepEqual(c.Style.Fg, ansi.IndexedColor(238)) {
				return false
			}
		}
	}
	return true
}

type devinInputFrame struct {
	Lines                                           []string
	Row, Column                                     int
	InitialStyles, TypedStyles, BracketedPaste, Raw bool
	ApprovalOnce                                    bool
}

func devinInitialPrompt(f devinInputFrame) bool {
	return f.Raw && f.InitialStyles && f.BracketedPaste && f.Column == 2 && f.Row >= 1 && f.Row < 39 && len(f.Lines) == 40 && f.Lines[f.Row] == "❭ Ask Devin to build features, fix bugs, or work on your code" && f.Lines[f.Row-1] == strings.Repeat("─", 120) && f.Lines[f.Row+1] == strings.Repeat("─", 120)
}
func TestDevinProtocolInitialPromptFrame(t *testing.T) {
	for _, row := range []int{2, 13, 30} {
		s := newDevinScreen()
		paint := fmt.Sprintf("\x1b[?2004h\x1b[%d;1H\x1b[38;5;238m%s\x1b[%d;1H\x1b[0m❭ \x1b[38;5;244mAsk Devin to build features, fix bugs, or work on your code\x1b[%d;1H\x1b[38;5;238m%s\x1b[0m\x1b[%d;3H", row, strings.Repeat("─", 120), row+1, row+2, strings.Repeat("─", 120), row+1)
		if e := s.feed([]byte(paint)); e != nil {
			t.Fatal(e)
		}
		lines, y, ok := s.visibleLines()
		f := devinInputFrame{Lines: lines, Row: y, Column: s.terminal.CursorPosition().X, InitialStyles: s.initialPromptStyles(), BracketedPaste: s.bracketed, Raw: true}
		if !ok || !devinInitialPrompt(f) {
			t.Fatal("observed-style relative prompt rejected")
		}
		f.Raw = false
		if devinInitialPrompt(f) {
			t.Fatal("canonical input accepted")
		}
		f.Raw = true
		f.Column = 3
		if devinInitialPrompt(f) {
			t.Fatal("wrong cursor accepted")
		}
	}
}

func (s *devinScreen) typedPromptStyles() bool {
	pos := s.terminal.CursorPosition()
	if s.failure != nil || s.updating || !s.visible || s.framing.State() != parser.GroundState || pos.Y < 2 || pos.Y >= 39 || pos.X < 2 || pos.X >= 120 {
		return false
	}
	for _, y := range []int{pos.Y - 1, pos.Y} {
		for x := 0; x < 120; x++ {
			c := s.terminal.CellAt(x, y)
			if c == nil || c.Style.Attrs != 0 || c.Style.Fg != nil || c.Style.Bg != nil {
				return false
			}
		}
	}
	for _, y := range []int{pos.Y - 2, pos.Y + 1} {
		for x := 0; x < 120; x++ {
			c := s.terminal.CellAt(x, y)
			if c == nil || c.Content != "─" || c.Style.Attrs != 0 || c.Style.Bg != nil || !reflect.DeepEqual(c.Style.Fg, ansi.IndexedColor(238)) {
				return false
			}
		}
	}
	return true
}

// The menu intentionally hides the cursor. This separate predicate never
// relaxes the editable prompt's visible-cursor requirement.
func (s *devinScreen) approvalOnceMenu(server, tool string) bool {
	p := s.terminal.CursorPosition()
	if s.failure != nil || s.visible || s.updating || s.framing.State() != parser.GroundState || !s.bracketed || p.X != 34 || p.Y < 9 || p.Y >= 40 {
		return false
	}
	rows := []string{" ⏺ mcp__" + server + "__" + tool + "(…)", "", "❭ 1 Yes  (Approve once)", "· 2 Yes, allow calling " + tool + " on the " + server + " MCP server", "· 3 Yes, always allow calling " + tool + " on the " + server + " MCP server", "· 4 Yes, allow calling all tools on the " + server + " MCP server", "· 5 Yes, always allow calling tools on the " + server + " MCP server", "· 6 Yes, switch to bypass mode", "· 7 No", "↑↓ select · ↵ confirm · esc cancel"}
	for i, text := range rows {
		chars := []rune(text)
		for x := 0; x < 120; x++ {
			c := s.terminal.CellAt(x, p.Y-9+i)
			if c == nil {
				return false
			}
			want := " "
			if x < len(chars) {
				want = string(chars[x])
			}
			if c.Content != want && !(want == " " && c.Content == "") {
				return false
			}
			var fg, bg color.Color
			attrs := c.Style.Attrs & 0
			switch {
			case i == 0 && (x == 1 || x == 2):
				fg = ansi.IndexedColor(78)
			case i == 2:
				bg = ansi.IndexedColor(234)
				if x == 0 || x >= 4 && x <= 6 {
					fg = ansi.IndexedColor(81)
					attrs = uv.AttrBold
				} else if x == 2 || x >= 9 && x <= 22 {
					fg = ansi.IndexedColor(244)
				}
			case i >= 3 && i <= 8 && (x == 0 || x == 2):
				fg = ansi.IndexedColor(244)
			case i == 9 && want != " ":
				fg = ansi.IndexedColor(244)
			}
			if c.Style.Attrs != attrs || !reflect.DeepEqual(c.Style.Fg, fg) || !reflect.DeepEqual(c.Style.Bg, bg) {
				return false
			}
		}
	}
	return true
}

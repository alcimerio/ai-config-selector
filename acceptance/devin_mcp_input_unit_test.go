package acceptance_test

import (
	"os"
	"testing"
)

const observedDevinPrompt = "Use mcp_call_tool once with server_name acs-synthetic, tool_name record_receipt, arguments {}, then respond READY. Do not use any other tool."

func capturedDevinInputFrame(t *testing.T, name string, tail []byte) devinInputFrame {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	s := newDevinScreen()
	if e = s.feed(b); e != nil {
		t.Fatal(e)
	}
	if e = s.feed(tail); e != nil {
		t.Fatal(e)
	}
	lines, row, ok := s.visibleLines()
	return devinInputFrame{Lines: lines, Row: row, Column: s.terminal.CursorPosition().X, InitialStyles: s.initialPromptStyles(), TypedStyles: s.typedPromptStyles(), BracketedPaste: s.bracketed, Raw: ok}
}
func TestDevinProtocolObservedStagedInput(t *testing.T) {
	initial := capturedDevinInputFrame(t, "devin-initial-prompt.vt", nil)
	typed := capturedDevinInputFrame(t, "devin-pasted-prompt.vt", nil)
	paste := []byte("\x1b[200~" + observedDevinPrompt + "\x1b[201~")
	p := devinInputProgress{stage: "paste"}
	if e := p.prepare(initial, append(append([]byte{}, paste...), 13)); e == nil {
		t.Fatal("combined paste Enter accepted")
	}
	if p.stage != "paste" {
		t.Fatal("refused write changed stage")
	}
	if e := p.prepare(initial, paste); e != nil {
		t.Fatal(e)
	}
	if p.stage != "submit" {
		t.Fatal("paste inferred submission")
	}
	if e := p.prepare(initial, []byte{13}); e == nil {
		t.Fatal("historical placeholder accepted Enter")
	}
	if e := p.prepare(typed, []byte{13}); e != nil {
		t.Fatal(e)
	}
	if p.stage != "await-request" {
		t.Fatal("Enter inferred model consumption")
	}
	if e := p.prepare(typed, []byte{13}); e == nil {
		t.Fatal("repeated Enter accepted")
	}
	if e := p.observedModel(0, 0); e != nil || p.stage != "await-request" {
		t.Fatal("no model advanced")
	}
	if e := p.observedModel(1, 0); e != nil || p.stage != "await-request" {
		t.Fatal("incomplete response advanced")
	}
	if e := p.observedModel(1, 1); e != nil || p.stage != "approval" {
		t.Fatal("actual model progression not recognized")
	}
	for _, stage := range []string{"paste", "submit"} {
		q := devinInputProgress{stage: stage}
		if q.observedModel(1, 1) == nil {
			t.Fatal("model before Enter accepted")
		}
	}
}
func TestDevinProtocolRenderedInputRefusals(t *testing.T) {
	if !devinRenderedPrompt(capturedDevinInputFrame(t, "devin-pasted-prompt.vt", nil), observedDevinPrompt) {
		t.Fatal("actual typed frame refused")
	}
	for _, tail := range []string{"\x1b[2J", "\x1b[?25l", "\x1b[?2026h", "\x1b[", "\xe2\x9d", "\x1b[15;26H\x1b[8mX\x1b[15;26H", "\x1b[15;26H\x1b[31mX\x1b[15;26H"} {
		if devinRenderedPrompt(capturedDevinInputFrame(t, "devin-pasted-prompt.vt", []byte(tail)), observedDevinPrompt) {
			t.Fatal("invalid current frame accepted")
		}
	}
	f := capturedDevinInputFrame(t, "devin-pasted-prompt.vt", nil)
	f.Raw = false
	if devinRenderedPrompt(f, observedDevinPrompt) {
		t.Fatal("nonraw accepted")
	}
	f.Raw = true
	f.Column--
	if devinRenderedPrompt(f, observedDevinPrompt) {
		t.Fatal("cursor mismatch accepted")
	}
	if devinRenderedPrompt(capturedDevinInputFrame(t, "devin-pasted-prompt.vt", nil), observedDevinPrompt+" changed") {
		t.Fatal("wrong exact prompt accepted")
	}
}

func TestDevinProtocolSubmissionBoundary(t *testing.T) {
	attached := func() *devinDriver {
		d := nativeDevinTestDriver(t)
		for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}} {
			nativeDevinPhase(t, d, a...)
			if d.phase != "attached" {
				if e := d.end(true); e != nil {
					t.Fatal(e)
				}
			}
		}
		d.submissionRequired = true
		return d
	}
	t.Run("premature", func(t *testing.T) {
		d := attached()
		w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("unused", "prompt", 1))
		if w.Code != 409 || d.models != 0 || d.failure == nil {
			t.Fatal("premature model accepted")
		}
		if d.submitInput(func() error { t.Fatal("write attempted after premature HTTP"); return nil }) == nil {
			t.Fatal("prior premature HTTP did not refuse submission")
		}
	})
	t.Run("write-failure", func(t *testing.T) {
		d := attached()
		if d.submitInput(func() error { return os.ErrDeadlineExceeded }) == nil || d.submitAuthorized || d.failure == nil {
			t.Fatal("failed write authorized model")
		}
	})
	t.Run("complete", func(t *testing.T) {
		d := attached()
		if e := d.submitInput(func() error {
			if d.mu.TryLock() {
				d.mu.Unlock()
				t.Fatal("submission write not protected by model mutex")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("unused", "prompt", 1))
		if w.Code != 200 || d.models != 1 || d.modelWrites != 1 {
			t.Fatal("completed submission rejected")
		}
		if d.submitInput(func() error { t.Fatal("repeated write attempted"); return nil }) == nil {
			t.Fatal("duplicate submission accepted")
		}
	})
}

func TestDevinProtocolObservedApprovalOnce(t *testing.T) {
	raw, e := os.ReadFile("testdata/devin-approval-menu.vt")
	if e != nil {
		t.Fatal(e)
	}
	replay := func(tail string) *devinScreen {
		s := newDevinScreen()
		if e = s.feed(raw); e != nil {
			t.Fatal(e)
		}
		if e = s.feed([]byte(tail)); e != nil {
			t.Fatal(e)
		}
		return s
	}
	s := replay("")
	if !s.approvalOnceMenu("acs-synthetic", "record_receipt") {
		t.Fatal("actual menu refused")
	}
	if s.approvalOnceMenu("fixture", "acs_allowed_echo") {
		t.Fatal("research identity accepted for native fixture")
	}
	if _, _, visible := s.visibleLines(); visible {
		t.Fatal("hidden menu relaxed editable cursor requirement")
	}
	for _, tail := range []string{"\x1b[2J", "\x1b[?2026h", "\x1b[?25h", "\x1b[", "\xe2\x9d", "\x1b[16;4HX\x1b[25;35H", "\x1b[18;1H.\x1b[25;35H", "\x1b[18;5H\x1b[8mY\x1b[25;35H", "\x1b[18;5H\x1b[31mY\x1b[25;35H"} {
		if replay(tail).approvalOnceMenu("acs-synthetic", "record_receipt") {
			t.Fatal("invalid approval frame accepted")
		}
	}
	p := devinInputProgress{stage: "approval"}
	f := devinInputFrame{Raw: true, BracketedPaste: true, ApprovalOnce: true}
	if p.prepare(f, []byte{'y'}) == nil {
		t.Fatal("unobserved key accepted")
	}
	if e = p.prepare(f, []byte{13}); e != nil || p.stage != "await-result" {
		t.Fatal("one selected Enter refused")
	}
	if p.prepare(f, []byte{13}) == nil {
		t.Fatal("repeat approval accepted")
	}
	p = devinInputProgress{stage: "approval"}
	f.ApprovalOnce = false
	if p.prepare(f, []byte{13}) == nil {
		t.Fatal("generic Enter approved")
	}
}

func TestDevinProtocolObservedIdleExit(t *testing.T) {
	f := capturedDevinInputFrame(t, "devin-success-idle.vt", nil)
	if !devinExitReady(f) {
		t.Fatal("actual successful idle refused")
	}
	b, e := devinNativeInput(f, "exit")
	if e != nil || len(b) != 1 || b[0] != 4 {
		t.Fatal("documented exit not selected")
	}
	p := devinInputProgress{stage: "exit"}
	if e = p.prepare(f, b); e != nil || p.stage != "finished" {
		t.Fatal("exit state not completed")
	}
	if p.prepare(f, b) == nil {
		t.Fatal("repeat exit accepted")
	}
	for _, tail := range []string{"\x1b[2J", "\x1b[?25l", "\x1b[?2026h", "\x1b[", "\xe2\x9d", "\x1b[22;3HX\x1b[22;3H"} {
		if devinExitReady(capturedDevinInputFrame(t, "devin-success-idle.vt", []byte(tail))) {
			t.Fatal("nonempty/invalid idle accepted")
		}
	}
	f.Lines[f.Row-3] = " ERROR"
	if devinExitReady(f) {
		t.Fatal("missing READY accepted")
	}
	f = capturedDevinInputFrame(t, "devin-initial-prompt.vt", nil)
	if devinExitReady(f) {
		t.Fatal("initial idle inferred completion")
	}
	p = devinInputProgress{stage: "exit"}
	if p.prepare(f, []byte{13}) == nil {
		t.Fatal("unobserved exit key accepted")
	}
}

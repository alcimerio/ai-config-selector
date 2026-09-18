package acceptance_test

import (
	"errors"
	"testing"
)

// finalSuccess is deliberately separate from per-phase settlement: natural
// preflight exits are legal, but never imply the attached proof completed.
func (d *devinDriver) finalSuccess() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return d.failure
	}
	if d.generation != 3 || d.phase != "attached" || !d.ended || d.active != 0 || d.models != 4 || d.modelWrites != 4 {
		return errors.New("incomplete native Devin conversation")
	}
	if d.submissionRequired && !d.guardedExit {
		return errors.New("native exit not guarded")
	}
	models := 0
	ancillary := 0
	for _, r := range d.receipts {
		if !r.BodyComplete || len(r.Body) != r.Bytes {
			return errors.New("incomplete captured HTTP body")
		}
		if !r.Complete {
			if !d.guardedExit || !r.AncillaryDisconnect || r.ReplyComplete || r.Phase != "attached" || r.Path != devinAnalytics || r.Method != "POST" || r.ContentType != "application/proto" || r.Status != 501 || r.ResponseContentType != "application/json" || r.ResponseBytes != len(`{"code":"unimplemented","message":"ACS synthetic local driver"}`) || r.ReplyError != "broken-pipe" {
				return errors.New("incomplete required HTTP receipt")
			}
			ancillary++
		} else if !r.ReplyComplete || r.AncillaryDisconnect {
			return errors.New("inconsistent HTTP receipt")
		}

		if r.Path == devinModel && r.Status == 200 {
			if r.Phase != "attached" {
				return errors.New("model response outside attached phase")
			}
			models++
		}
	}
	if ancillary != d.ancillaryDisconnects || ancillary > 2 {
		return errors.New("ancillary disconnect accounting")
	}
	if models != 4 {
		return errors.New("missing completed model receipts")
	}
	return nil
}
func TestDevinProtocolNaturalExitIsNotCompletion(t *testing.T) {
	d := nativeDevinTestDriver(t)
	for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}} {
		nativeDevinPhase(t, d, a...)
		if e := d.end(true); e != nil {
			t.Fatal(e)
		}
	}
	if d.finalSuccess() == nil {
		t.Fatal("empty natural exit passed")
	}
	d.failure = errors.New("recorded failure")
	if d.finalSuccess() != d.failure {
		t.Fatal("lost failure")
	}
}

func TestDevinProtocolFinalReceiptRequirements(t *testing.T) {
	makeComplete := func() *devinDriver {
		d := nativeDevinTestDriver(t)
		for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}} {
			nativeDevinPhase(t, d, a...)
			_ = d.end(true)
		}
		nativeDevinPhase(t, d, "--respect-workspace-trust", "false")
		for _, v := range []struct{ id, text string }{{"initial", "unused"}, {"acs-list-servers-1", "fixture"}, {"acs-list-tools-1", "acs_allowed_echo"}, {"acs-call-1", "ACS_MCP_TOOL_OK"}} {
			w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest(v.id, v.text, 4))
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
		}
		_ = d.end(true)
		return d
	}
	if e := makeComplete().finalSuccess(); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name   string
		change func(*devinDriver)
	}{{"partial", func(d *devinDriver) { d.modelWrites = 3 }}, {"active", func(d *devinDriver) { d.active = 1 }}, {"missing", func(d *devinDriver) { d.receipts = d.receipts[:3] }}, {"incomplete", func(d *devinDriver) { d.receipts[0].Complete = false }}, {"wrong-phase", func(d *devinDriver) { d.receipts[0].Phase = "auth" }}} {
		t.Run(tc.name, func(t *testing.T) {
			d := makeComplete()
			tc.change(d)
			if d.finalSuccess() == nil {
				t.Fatal("accepted incomplete proof")
			}
		})
	}
}

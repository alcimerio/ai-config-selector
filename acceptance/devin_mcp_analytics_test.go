package acceptance_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

type devinFailingReply struct {
	header http.Header
	err    error
	status int
}

func (w *devinFailingReply) Header() http.Header         { return w.header }
func (w *devinFailingReply) WriteHeader(n int)           { w.status = n }
func (w *devinFailingReply) Write(b []byte) (int, error) { return 0, w.err }
func devinCompletedBeforeExit(t *testing.T) *devinDriver {
	t.Helper()
	d := nativeDevinTestDriver(t)
	for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}} {
		nativeDevinPhase(t, d, a...)
		if d.phase != "attached" {
			if e := d.end(true); e != nil {
				t.Fatal(e)
			}
		}
	}
	for _, v := range []struct{ id, text string }{{"unused", "initial"}, {"acs-list-servers-1", "fixture"}, {"acs-list-tools-1", "acs_allowed_echo"}, {"acs-call-1", "ACS_MCP_TOOL_OK"}} {
		if w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest(v.id, v.text, 4)); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	d.submissionRequired = true
	d.submitAuthorized = true
	return d
}
func devinDisconnectRequest(d *devinDriver, path, ct string, body []byte, extraLength int, err error) *devinFailingReply {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.ContentLength += int64(extraLength)
	r.Header.Set("Content-Type", ct)
	w := &devinFailingReply{header: make(http.Header), err: err}
	d.ServeHTTP(w, r)
	return w
}
func TestDevinProtocolAncillaryExitDisconnect(t *testing.T) {
	d := devinCompletedBeforeExit(t)
	if e := d.markGuardedExit(); e != nil {
		t.Fatal(e)
	}
	body := []byte{10, 3, 'a', 'b', 'c'}
	for i := 0; i < 2; i++ {
		w := devinDisconnectRequest(d, devinAnalytics, "application/proto", body, 0, syscall.EPIPE)
		if w.status != 501 || d.failure != nil {
			t.Fatal("bounded known analytics disconnect refused")
		}
	}
	for _, r := range d.receipts[4:] {
		if !r.BodyComplete || r.ReplyComplete || r.Complete || !r.AncillaryDisconnect || !bytes.Equal(r.Body, body) || r.ReplyError != "broken-pipe" {
			t.Fatal("body and reply states collapsed")
		}
	}
	if e := d.end(true); e != nil {
		t.Fatal(e)
	}
	if e := d.finalSuccess(); e != nil {
		t.Fatal(e)
	}
}
func TestDevinProtocolAncillaryDisconnectRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, path, ct string
		err            error
		extra          int
		guard          bool
	}{
		{"before-exit", devinAnalytics, "application/proto", syscall.EPIPE, 0, false},
		{"auth", devinSeat + "GetUserStatus", "application/proto", syscall.EPIPE, 0, true},
		{"team", devinSeat + "GetCliTeamSettings", "application/proto", syscall.EPIPE, 0, true},
		{"model", devinModel, "application/connect+proto", syscall.EPIPE, 0, true},
		{"unknown", "/unknown", "application/proto", syscall.EPIPE, 0, true},
		{"generic-write", devinAnalytics, "application/proto", syscall.EIO, 0, true},
		{"short-write", devinAnalytics, "application/proto", nil, 0, true},
		{"wrong-type", devinAnalytics, "application/json", syscall.EPIPE, 0, true},
		{"incomplete-body", devinAnalytics, "application/proto", syscall.EPIPE, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := devinCompletedBeforeExit(t)
			if tc.guard {
				if e := d.markGuardedExit(); e != nil {
					t.Fatal(e)
				}
			}
			devinDisconnectRequest(d, tc.path, tc.ct, []byte{8, 1}, tc.extra, tc.err)
			if d.failure == nil || d.ancillaryDisconnects != 0 {
				t.Fatal("required failure suppressed")
			}
		})
	}
	t.Run("third", func(t *testing.T) {
		d := devinCompletedBeforeExit(t)
		_ = d.markGuardedExit()
		for i := 0; i < 3; i++ {
			devinDisconnectRequest(d, devinAnalytics, "application/proto", nil, 0, syscall.EPIPE)
		}
		if d.failure == nil || d.ancillaryDisconnects != 2 {
			t.Fatal("disconnect cap missing")
		}
	})
	t.Run("secret", func(t *testing.T) {
		d := devinCompletedBeforeExit(t)
		_ = d.markGuardedExit()
		devinDisconnectRequest(d, devinAnalytics, "application/proto", []byte(devinSelectedSecret), 0, syscall.EPIPE)
		if d.failure == nil || d.ancillaryDisconnects != 0 {
			t.Fatal("secret body accepted")
		}
	})
}
func TestDevinProtocolExitGuardAndWriteFailure(t *testing.T) {
	d := nativeDevinTestDriver(t)
	if d.markGuardedExit() == nil {
		t.Fatal("guard before proof accepted")
	}
	d = devinCompletedBeforeExit(t)
	if e := d.markGuardedExit(); e != nil {
		t.Fatal(e)
	}
	if d.markGuardedExit() == nil {
		t.Fatal("repeated guard accepted")
	}
	d.fail(errors.New("bounded Ctrl+D write failed"))
	if d.finalSuccess() == nil {
		t.Fatal("failed exit write excused")
	}
}

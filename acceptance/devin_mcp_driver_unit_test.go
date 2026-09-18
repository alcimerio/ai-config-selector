package acceptance_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeDevinTestDriver(t *testing.T) *devinDriver {
	t.Helper()
	return &devinDriver{member: "locked", home: "/private/case/session/home", serverProof: func(int) error { return nil }, listingProof: func(stage int, result string) error {
		want := []string{"fixture", "acs_allowed_echo"}
		if stage < 1 || stage > 2 || result != want[stage-1] {
			return errors.New("complete listing mismatch")
		}
		return nil
	}}
}
func nativeDevinPhase(t *testing.T, d *devinDriver, args ...string) {
	t.Helper()
	if e := d.begin(devinPhaseReceipt{PID: 42, Argv: args, MemberSHA256: "locked", SessionHome: "/private/case/session/home"}); e != nil {
		t.Fatal(e)
	}
}
func nativeDevinPOST(d *devinDriver, path, ct string, b []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w
}
func nativeDevinRequest(id, text string, role byte) []byte {
	message := []byte{16, role}
	message = append(message, devinBytes(3, []byte(text))...)
	message = append(message, devinBytes(7, []byte(id))...)
	payload := devinBytes(3, message)
	body := make([]byte, 5)
	binary.BigEndian.PutUint32(body[1:], uint32(len(payload)))
	return append(body, payload...)
}
func TestDevinProtocolPhaseBudgetsAndCompleteConversation(t *testing.T) {
	d := nativeDevinTestDriver(t)
	for _, args := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}} {
		nativeDevinPhase(t, d, args...)
		for i := 0; i < 3; i++ {
			w := nativeDevinPOST(d, devinSeat+"GetCliTeamSettings", "application/proto", nil)
			want := 200
			if i == 2 {
				want = 501
			}
			if w.Code != want {
				t.Fatalf("phase%s response%d=%d", d.phase, i, w.Code)
			}
		}
		if d.phase != "attached" {
			if e := d.end(true); e != nil {
				t.Fatal(e)
			}
		}
	}
	for i, input := range []struct{ id, text string }{{"unused", "initial"}, {"acs-list-servers-1", "fixture"}, {"acs-list-tools-1", "acs_allowed_echo"}, {"acs-call-1", "ACS_MCP_TOOL_OK"}} {
		w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest(input.id, input.text, 4))
		if w.Code != 200 {
			t.Fatalf("turn%d=%d failure%v", i, w.Code, d.failure)
		}
		b := w.Body.Bytes()
		n := int(binary.BigEndian.Uint32(b[1:5]))
		if !bytes.Equal(b[5+n:], []byte{2, 0, 0, 0, 2, '{', '}'}) {
			t.Fatal("Connect end frame")
		}
	}
	if d.models != 4 || d.modelWrites != 4 || d.failure != nil {
		t.Fatalf("driver failed%v", d.failure)
	}
	if e := d.end(true); e != nil {
		t.Fatal(e)
	}
	for _, r := range d.receipts {
		if !r.Complete {
			t.Fatal("missing completed-write receipt")
		}
	}
}
func TestDevinProtocolRefusesUntrustedPhaseAndPreflightModel(t *testing.T) {
	d := nativeDevinTestDriver(t)
	if e := d.begin(devinPhaseReceipt{PID: 42, Argv: []string{"skills", "list", "--json"}, MemberSHA256: "wrong", SessionHome: d.home}); e == nil {
		t.Fatal("wrong member")
	}
	nativeDevinPhase(t, d, "skills", "list", "--json")
	if e := d.begin(devinPhaseReceipt{PID: 43, Argv: []string{"auth", "status"}, MemberSHA256: d.member, SessionHome: d.home}); e == nil {
		t.Fatal("missing prior settlement")
	}
	if w := nativeDevinPOST(d, devinModel, "application/connect+proto", nil); w.Code != 403 || d.failure == nil {
		t.Fatal("model served to preflight")
	}
}

func TestDevinPhaseCompletionDiagnosticSeparatesFailureClasses(t *testing.T) {
	want := []string{"skills", "list", "--json"}
	validStarted := devinPhaseStartedReceipt{PID: 11, Parent: 7, Argv: want}
	validDone := devinPhaseDoneReceipt{PID: 11, Parent: 7, ExitCode: 0}
	valid := func() string { return devinPhaseCompletionDiagnostic("skills", 7, validStarted, validDone, want) }
	if got := valid(); got != "" {
		t.Fatalf("valid completion diagnostic=%q", got)
	}
	unknown := devinPhaseCompletionDiagnostic("private-phase", 7, validStarted, validDone, want)
	if !strings.Contains(unknown, "phase=unknown") || strings.Contains(unknown, "private-phase") {
		t.Fatalf("unknown phase leaked: %q", unknown)
	}
	cases := []struct {
		name   string
		mutate func(*devinPhaseStartedReceipt, *devinPhaseDoneReceipt)
		want   string
	}{
		{name: "parent", mutate: func(s *devinPhaseStartedReceipt, _ *devinPhaseDoneReceipt) { s.Parent = 8 }, want: "started-parent=false"},
		{name: "pid", mutate: func(_ *devinPhaseStartedReceipt, d *devinPhaseDoneReceipt) { d.PID = 12 }, want: "pid-match=false"},
		{name: "forced", mutate: func(_ *devinPhaseStartedReceipt, d *devinPhaseDoneReceipt) { d.Forced = true }, want: "forced=true"},
		{name: "exit", mutate: func(_ *devinPhaseStartedReceipt, d *devinPhaseDoneReceipt) { d.ExitCode = 17 }, want: "exit-code=17"},
		{name: "argv", mutate: func(s *devinPhaseStartedReceipt, _ *devinPhaseDoneReceipt) { s.Argv = []string{"auth", "status"} }, want: "argv=false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			started, done := validStarted, validDone
			tc.mutate(&started, &done)
			if got := devinPhaseCompletionDiagnostic("skills", 7, started, done, want); !strings.Contains(got, tc.want) {
				t.Fatalf("diagnostic=%q missing %q", got, tc.want)
			}
		})
	}
}
func TestDevinProtocolCorrelationRefusals(t *testing.T) {
	valid := nativeDevinRequest("call", "OK", 4)
	for _, tc := range []struct {
		name string
		b    []byte
		id   string
	}{{"wrong-role", nativeDevinRequest("call", "OK", 2), "call"}, {"wrong-id", valid, "other"}, {"compressed", append([]byte{1}, valid[1:]...), "call"}, {"truncated", valid[:len(valid)-1], "call"}, {"extra-frame", append(append([]byte{}, valid...), 0, 0, 0, 0, 0), "call"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := devinResult(tc.b, tc.id); e == nil {
				t.Fatal("accepted malformed correlation")
			}
		})
	}
	duplicate := append([]byte{}, valid[5:]...)
	duplicate = append(duplicate, valid[5:]...)
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[1:], uint32(len(duplicate)))
	if _, e := devinResult(append(b, duplicate...), "call"); e == nil {
		t.Fatal("duplicate result")
	}
}
func TestDevinProtocolIndependentEffectRequired(t *testing.T) {
	d := nativeDevinTestDriver(t)
	for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}} {
		nativeDevinPhase(t, d, a...)
		_ = d.end(true)
	}
	nativeDevinPhase(t, d, "--respect-workspace-trust", "false")
	nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("initial", "unused", 4))
	d.serverProof = func(int) error { return errors.New("no independently observed listing") }
	if w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("acs-list-servers-1", "fixture", 4)); w.Code != 409 || d.models != 2 || d.modelWrites != 1 {
		t.Fatal("result text substituted for independent proof")
	}
}

func TestDevinProtocolNoDefaultListingHeuristic(t *testing.T) {
	d := nativeDevinTestDriver(t)
	for _, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}} {
		nativeDevinPhase(t, d, a...)
		_ = d.end(true)
	}
	nativeDevinPhase(t, d, "--respect-workspace-trust", "false")
	nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("initial", "unused", 4))
	d.listingProof = nil
	w := nativeDevinPOST(d, devinModel, "application/connect+proto", nativeDevinRequest("acs-list-servers-1", "fixture", 4))
	if w.Code != 409 || d.modelWrites != 1 {
		t.Fatal("missing listing contract accepted")
	}
}
func TestDevinProtocolRejectsNonLoopbackListener(t *testing.T) {
	if close, err := startDevinListener(nativeDevinTestDriver(t), "0.0.0.0:0"); err == nil || close != nil {
		t.Fatal("wildcard listener accepted")
	}
}

func TestDevinProtocolCredentialCopy(t *testing.T) {
	home := t.TempDir()
	endpoint, e := copyDevinSyntheticCredentials(home)
	if e != nil {
		t.Fatal(e)
	}
	if endpoint == "" {
		t.Fatal("missing saved endpoint")
	}
	if _, e = copyDevinSyntheticCredentials(home); e == nil {
		t.Fatal("replaced credentials")
	}
	b, e := os.ReadFile(filepath.Join(home, ".local", "share", "devin", "credentials.toml"))
	if e != nil || !bytes.Equal(b, devinSyntheticCredentials) {
		t.Fatal("not byte exact", e)
	}
}

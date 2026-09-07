package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

const goldenSessionID = "ses_abcd234567abcdef234567abcd"

type goldenSessionOperations struct {
	failure error
	empty   bool
	corrupt bool
}

func (operations goldenSessionOperations) List(sessionops.State) (sessionops.ListResult, error) {
	if operations.failure != nil {
		return sessionops.ListResult{}, operations.failure
	}
	if operations.empty {
		return sessionops.ListResult{SchemaVersion: 1, Sessions: []sessionops.PublicSession{}, UntrackedCount: 0}, nil
	}
	if operations.corrupt {
		return sessionops.ListResult{SchemaVersion: 1, Sessions: []sessionops.PublicSession{{
			ID: goldenSessionID, State: sessionops.StateCorrupt, Observation: "durable",
			Recovery: sessionops.Recovery{Allowed: false, Action: "none"},
		}}, UntrackedCount: 0}, nil
	}
	return sessionops.ListResult{SchemaVersion: 1, Sessions: []sessionops.PublicSession{{
		ID: goldenSessionID, State: sessionops.StateRetryable, Observation: "durable", Target: "codex",
		CreatedAt: "2026-09-07T12:00:00Z", UpdatedAt: "2026-09-07T12:00:04Z", Revision: 3,
		Recovery: sessionops.Recovery{Allowed: true, Action: "verify-proof"},
	}}, UntrackedCount: 2}, nil
}
func (operations goldenSessionOperations) Inspect(string) (sessionops.InspectResult, error) {
	if operations.failure != nil {
		return sessionops.InspectResult{}, operations.failure
	}
	listed, _ := operations.List("")
	return sessionops.InspectResult{SchemaVersion: 1, Session: listed.Sessions[0]}, nil
}
func (operations goldenSessionOperations) Recover(string) (sessionops.RecoverResult, error) {
	if operations.failure != nil {
		return sessionops.RecoverResult{SchemaVersion: 1, ID: goldenSessionID, Outcome: "busy", State: sessionops.StateActive, Revision: 3}, operations.failure
	}
	return sessionops.RecoverResult{SchemaVersion: 1, ID: goldenSessionID, Outcome: "removed", State: sessionops.StateRemoved, Revision: 7}, nil
}

func TestCodexSessionRecoveryMapsOnlySemanticContention(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		busy bool
	}{
		{name: "wrapped identity busy", err: fmt.Errorf("adapter: %w", codexauthresource.ErrIdentityBusy), busy: true},
		{name: "deadline", err: context.DeadlineExceeded, busy: true},
		{name: "cancelled", err: context.Canceled, busy: true},
		{name: "busy message", err: errors.New("busy"), busy: false},
		{name: "in use message", err: errors.New("identity is in use"), busy: false},
		{name: "timeout message", err: errors.New("provider timeout"), busy: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mapped := mapCodexSessionRecoveryError(test.err)
			if errors.Is(mapped, sessionops.ErrAuthBusy) != test.busy {
				t.Fatalf("mapped error = %v, busy=%t", mapped, test.busy)
			}
			if !test.busy && !errors.Is(mapped, test.err) {
				t.Fatalf("unrelated error changed: %v", mapped)
			}
		})
	}
}

func TestSessionOperationOutputGoldens(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		ops  goldenSessionOperations
		code int
	}{
		{name: "list.human", args: []string{"session", "list"}},
		{name: "list.json", args: []string{"session", "list", "--json"}},
		{name: "list-empty.human", args: []string{"session", "list"}, ops: goldenSessionOperations{empty: true}},
		{name: "list-empty.json", args: []string{"session", "list", "--json"}, ops: goldenSessionOperations{empty: true}},
		{name: "list-corrupt.json", args: []string{"session", "list", "--json"}, ops: goldenSessionOperations{corrupt: true}},
		{name: "inspect.human", args: []string{"session", "inspect", goldenSessionID}},
		{name: "inspect.json", args: []string{"session", "inspect", goldenSessionID, "--json"}},
		{name: "recover.human", args: []string{"session", "recover", goldenSessionID}},
		{name: "recover.json", args: []string{"session", "recover", goldenSessionID, "--json"}},
		{name: "recover-busy.json", args: []string{"session", "recover", goldenSessionID, "--json"}, ops: goldenSessionOperations{failure: errors.New("busy")}, code: 1},
		{name: "list-limit.json", args: []string{"session", "list", "--json"}, ops: goldenSessionOperations{failure: errors.New("session_registry_limit")}, code: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := App{Output: &stdout, ErrorOutput: &stderr, SessionOperations: test.ops}
			handled, code := app.RunSessionOperations(test.args, func() (string, error) {
				t.Fatal("golden operation discovered HOME")
				return "", nil
			})
			if !handled || code != test.code || stderr.Len() != 0 {
				t.Fatalf("result = (%t, %d, %q)", handled, code, stderr.String())
			}
			want, err := os.ReadFile(filepath.Join("testdata", "session-operations", test.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if stdout.String() != string(want) {
				t.Fatalf("output differs from %s:\nwant %q\n got %q", test.name, want, stdout.String())
			}
		})
	}
}

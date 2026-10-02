package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
func (operations goldenSessionOperations) ListPage(filter sessionops.State, _ string, _ int) (sessionops.ListResult, error) {
	return operations.List(filter)
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

func TestSessionListPaginationGrammar(t *testing.T) {
	for _, args := range [][]string{
		{"session", "list", "--limit", "1"},
		{"session", "list", "--limit", "512", "--json"},
		{"session", "list", "--after", goldenSessionID, "--state", "retryable", "--json", "--limit", "16"},
	} {
		if _, problem := parseCommand(args); problem != "" {
			t.Fatalf("parse %v: %s", args, problem)
		}
		if !SessionOperationsRequested(args) {
			t.Fatalf("page request did not select the pre-runtime route: %v", args)
		}
	}
}

type recordingSessionOperations struct {
	goldenSessionOperations
	listCalls, pageCalls int
	filter               sessionops.State
	after                string
	limit                int
	nextAfter            string
}

func (operations *recordingSessionOperations) List(filter sessionops.State) (sessionops.ListResult, error) {
	operations.listCalls++
	operations.filter = filter
	return operations.goldenSessionOperations.List(filter)
}

func (operations *recordingSessionOperations) ListPage(filter sessionops.State, after string, limit int) (sessionops.ListResult, error) {
	operations.pageCalls++
	operations.filter, operations.after, operations.limit = filter, after, limit
	result, err := operations.goldenSessionOperations.List(filter)
	result.NextAfter = operations.nextAfter
	return result, err
}

func TestSessionListDispatchAndContinuation(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		filter    sessionops.State
		after     string
		limit     int
		nextAfter string
		empty     bool
		json      bool
	}{
		{name: "complete default", args: []string{"session", "list"}},
		{name: "complete filtered JSON", args: []string{"session", "list", "--state", "retryable", "--json"}, filter: sessionops.StateRetryable, json: true},
		{name: "first page JSON", args: []string{"session", "list", "--limit", "1", "--json"}, limit: 1, nextAfter: goldenSessionID, json: true},
		{name: "filtered page", args: []string{"session", "list", "--after", goldenSessionID, "--limit", "512", "--state", "retryable"}, filter: sessionops.StateRetryable, after: goldenSessionID, limit: 512, nextAfter: goldenSessionID},
		{name: "empty filtered page", args: []string{"session", "list", "--state", "active", "--limit", "8"}, filter: sessionops.StateActive, limit: 8, nextAfter: goldenSessionID, empty: true},
		{name: "empty filtered JSON page", args: []string{"session", "list", "--state", "active", "--limit", "8", "--json"}, filter: sessionops.StateActive, limit: 8, nextAfter: goldenSessionID, empty: true, json: true},
		{name: "last page", args: []string{"session", "list", "--limit", "8", "--after", goldenSessionID}, after: goldenSessionID, limit: 8},
		{name: "last JSON page", args: []string{"session", "list", "--limit", "8", "--json"}, limit: 8, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &recordingSessionOperations{goldenSessionOperations: goldenSessionOperations{empty: test.empty}, nextAfter: test.nextAfter}
			var output, stderr bytes.Buffer
			app := App{Output: &output, ErrorOutput: &stderr, SessionOperations: operations}
			handled, code := app.RunSessionOperations(test.args, func() (string, error) {
				t.Fatal("list with injected operations discovered HOME")
				return "", nil
			})
			if !handled || code != 0 || stderr.Len() != 0 {
				t.Fatalf("list = (%t, %d, %q)", handled, code, stderr.String())
			}
			wantPageCalls := 0
			if test.limit != 0 {
				wantPageCalls = 1
			}
			if operations.pageCalls != wantPageCalls || operations.listCalls != 1-wantPageCalls || operations.filter != test.filter || operations.after != test.after || operations.limit != test.limit {
				t.Fatalf("dispatch = %+v", operations)
			}
			if test.json {
				if strings.Contains(output.String(), `"nextAfter"`) != (test.nextAfter != "") {
					t.Fatalf("incorrect optional cursor field: %q", output.String())
				}
				var result sessionops.ListResult
				decoder := json.NewDecoder(&output)
				if err := decoder.Decode(&result); err != nil {
					t.Fatal(err)
				}
				if result.NextAfter != test.nextAfter || (len(result.Sessions) == 0) != test.empty {
					t.Fatalf("JSON page = %+v", result)
				}
				var extra any
				if err := decoder.Decode(&extra); err != io.EOF {
					t.Fatalf("unexpected trailing JSON: %v, %v", extra, err)
				}
				return
			}
			if test.nextAfter == "" {
				if strings.Contains(output.String(), "Next page:") {
					t.Fatalf("spurious continuation: %q", output.String())
				}
				return
			}
			want := fmt.Sprintf("Next page: acs session list --limit %d --after %s", test.limit, test.nextAfter)
			if test.filter != "" {
				want += " --state " + string(test.filter)
			}
			if !strings.HasSuffix(output.String(), want+"\n") {
				t.Fatalf("page lacks continuation %q: %q", want, output.String())
			}
		})
	}
}

func TestSessionListPageFailureIsOneSanitizedDiagnostic(t *testing.T) {
	operations := &recordingSessionOperations{goldenSessionOperations: goldenSessionOperations{failure: errors.New("session_registry_limit")}}
	var output, stderr bytes.Buffer
	app := App{Output: &output, ErrorOutput: &stderr, SessionOperations: operations}
	handled, code := app.RunSessionOperations([]string{"session", "list", "--limit", "1", "--json"}, func() (string, error) {
		t.Fatal("page discovered HOME")
		return "", nil
	})
	if !handled || code != 1 || operations.pageCalls != 1 || operations.listCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("page failure = (%t, %d, %q), calls=%+v", handled, code, stderr.String(), operations)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "session-operations", "list-limit.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != string(want) {
		t.Fatalf("page failure output = %q, want %q", output.String(), want)
	}
}

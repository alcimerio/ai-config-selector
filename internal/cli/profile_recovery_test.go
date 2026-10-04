package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

type recoveryRepository struct {
	ProfileRepository
	outcome profilerepo.Outcome
	err     error
	calls   int
	cancel  context.CancelFunc
}

func (r *recoveryRepository) Recover(ctx context.Context) (profilerepo.Outcome, error) {
	r.calls++
	if r.cancel != nil {
		r.cancel()
	}
	return r.outcome, r.err
}

func TestProfileRecoveryExactOutcomesAndSanitization(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.NotCommitted, profilerepo.Committed, profilerepo.Unknown} {
		for _, required := range []bool{false, true} {
			for _, failure := range []error{nil, errors.New("private /Users/secret token=credential\x1b[31m"), profilerepo.ErrBusy, profilerepo.ErrUnsafe, context.Canceled} {
				t.Run(string(state), func(t *testing.T) {
					repository := &recoveryRepository{outcome: profilerepo.Outcome{State: state, RecoveryRequired: required}, err: failure}
					var output, stderr bytes.Buffer
					app := App{Repository: repository, Output: &output, ErrorOutput: &stderr}
					code := app.Run(context.Background(), []string{"profile", "recover", "--json"})
					var result struct {
						State            profilerepo.State               `json:"state"`
						RecoveryRequired bool                            `json:"recoveryRequired"`
						Diagnostic       *struct{ Code, Message string } `json:"diagnostic"`
					}
					if err := json.Unmarshal(output.Bytes(), &result); err != nil {
						t.Fatalf("invalid JSON: %v %s %s", err, output.String(), stderr.String())
					}
					if result.State != state || result.RecoveryRequired != required || repository.calls != 1 {
						t.Fatalf("outcome lost: %+v calls=%d", result, repository.calls)
					}
					if (code == 0) != (failure == nil && !required && state != profilerepo.Unknown) {
						t.Fatalf("false success: code=%d result=%+v", code, result)
					}
					if strings.Contains(output.String()+stderr.String(), "secret") || strings.Contains(output.String(), "credential") || strings.Contains(output.String(), "noPending") {
						t.Fatalf("unsafe/invented output: %s", output.String())
					}
					if failure != nil && state == profilerepo.NotCommitted && (result.Diagnostic == nil || !strings.Contains(result.Diagnostic.Message, "inspection")) {
						t.Fatalf("missing inspection limit: %s", output.String())
					}
				})
			}
		}
	}
}

func TestProfileRecoveryLaterCancellationPreservesCommittedOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository := &recoveryRepository{outcome: profilerepo.Outcome{State: profilerepo.Committed}, cancel: cancel}
	var output, stderr bytes.Buffer
	app := App{Repository: repository, Output: &output, ErrorOutput: &stderr}
	if code := app.Run(ctx, []string{"profile", "recover"}); code != 0 || !strings.Contains(output.String(), "committed") || strings.Contains(output.String(), "cancel") {
		t.Fatalf("late cancellation flattened commit: %d %s %s", code, output.String(), stderr.String())
	}
}

func TestProfileRecoveryGrammarAndHelpNeverRecover(t *testing.T) {
	for _, args := range [][]string{{"profile", "recover", "--help"}, {"help", "profile", "recover"}, {"profile", "recover", "NAME"}, {"profile", "recover", "--json", "--json"}, {"profile", "recover", "--force"}} {
		repository := &recoveryRepository{}
		var output, stderr bytes.Buffer
		app := App{Repository: repository, Output: &output, ErrorOutput: &stderr}
		app.Run(context.Background(), args)
		if repository.calls != 0 {
			t.Fatalf("grammar/help recovered: %v", args)
		}
		if strings.Contains(strings.Join(args, " "), "help") && !strings.Contains(output.String(), "acs profile recover") {
			t.Fatalf("missing recovery help: %s %s", output.String(), stderr.String())
		}
	}
}

func TestProfileRecoveryEarlyCancellationAndHomeFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output, stderr bytes.Buffer
	repository := &recoveryRepository{}
	app := App{Repository: repository, Output: &output, ErrorOutput: &stderr}
	handled, code := app.RunProfileRecovery(ctx, []string{"profile", "recover", "--json"}, func() (string, error) { t.Fatal("cancelled recovery looked up HOME"); return "", nil })
	if !handled || code != 130 || repository.calls != 0 || !strings.Contains(output.String(), "inspection") {
		t.Fatalf("early cancellation: %d %s", code, output.String())
	}
	output.Reset()
	app.Repository = nil
	_, code = app.RunProfileRecovery(context.Background(), []string{"profile", "recover", "--json"}, func() (string, error) { return "", errors.New("private /Users/secret") })
	if code != 1 || strings.Contains(output.String()+stderr.String(), "secret") {
		t.Fatalf("unsafe HOME error: %d %s %s", code, output.String(), stderr.String())
	}
}

func TestProfileRecoveryAbsentStorageNeverBootstraps(t *testing.T) {
	home := t.TempDir()
	var output, stderr bytes.Buffer
	app := App{Output: &output, ErrorOutput: &stderr}
	_, code := app.RunProfileRecovery(context.Background(), []string{"profile", "recover", "--json"}, func() (string, error) { return home, nil })
	if code != 0 || !strings.Contains(output.String(), `"state":"not_committed"`) {
		t.Fatalf("empty recovery: %d %s %s", code, output.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".acs")); !os.IsNotExist(err) {
		t.Fatalf("bootstrapped absent repository: %v", err)
	}
}

func TestProfileRecoveryExactHistoryAndStableOutput(t *testing.T) {
	identity := &profilerepo.HistoryIdentity{LineageID: "ln_" + strings.Repeat("1", 32), EventID: "ev_" + strings.Repeat("2", 32)}
	repository := &recoveryRepository{outcome: profilerepo.Outcome{State: profilerepo.Committed, History: identity}}
	var previous string
	for i := 0; i < 2; i++ {
		var output, stderr bytes.Buffer
		app := App{Repository: repository, Output: &output, ErrorOutput: &stderr}
		if code := app.Run(context.Background(), []string{"profile", "recover", "--json"}); code != 0 {
			t.Fatal(code, stderr.String())
		}
		var result struct {
			History profileRecoveryHistory `json:"history"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.History.LineageID != identity.LineageID || result.History.EventID != identity.EventID {
			t.Fatalf("lost exact identity: %s %v", output.String(), err)
		}
		if i > 0 && output.String() != previous {
			t.Fatal("unstable output")
		}
		previous = output.String()
	}
	// Read and other methods are nil through the embedded interface. Any inferred
	// transaction identity from later repository reads would panic here.
}

type recoveryFailedWriter struct{}

func (recoveryFailedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestProfileRecoveryReportingFailureDoesNotReplay(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		repository := &recoveryRepository{outcome: profilerepo.Outcome{State: profilerepo.Committed}}
		var stderr bytes.Buffer
		app := App{Repository: repository, Output: recoveryFailedWriter{}, ErrorOutput: &stderr}
		args := []string{"profile", "recover"}
		if jsonOutput {
			args = append(args, "--json")
		}
		if code := app.Run(context.Background(), args); code != 1 || repository.calls != 1 || strings.Contains(stderr.String(), "cancel") || !strings.Contains(stderr.String(), "reporting failed") {
			t.Fatalf("reporting failure: %d %d %s", code, repository.calls, stderr.String())
		}
	}
}

//go:build darwin || linux

package builder

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/creack/pty"
)

// Termination must not outpace an executing repository call. The saver
// deliberately ignores cancellation while settling its decision. SIGTERM is
// distinct from context cancellation and SIGINT: Bubble Tea's default handler
// emits QuitMsg for SIGTERM and would otherwise return a nil runtime error.
func TestMutationRuntimeCancellationWaitsForCommitOutcome(t *testing.T) {
	for _, termination := range []string{"context", "SIGTERM", "SIGINT", "Ctrl+C", "input-error", "input-error-with-cancel"} {
		for _, state := range []string{"success", "committed", "unknown"} {
			for _, flow := range []string{"create", "edit"} {
				t.Run(termination+"/"+state+"/"+flow, func(t *testing.T) {
					binding, registry := newBuilderFixture(t)
					model := newLoadedSkillsModel(t, "runtime", registry.NewDraft(), registry, binding, nil)
					entered, release := make(chan struct{}), make(chan struct{})
					model = model.WithSaver(func(context.Context, category.Draft) (string, error) {
						close(entered)
						<-release
						if state == "success" {
							return "saved", nil
						}
						return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.State(state), RecoveryRequired: true}, Err: context.Canceled}
					})
					if flow == "edit" {
						var err error
						save := model.save
						model, err = model.WithMutation(MutationOptions{Label: "Edit", Prepare: func(category.Draft) (PreparedMutation, error) {
							return PreparedMutation{Text: "exact preview", Save: save}, nil
						}})
						if err != nil {
							t.Fatal(err)
						}
					}
					model.overviewCursor = 1
					model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
					master, terminal, err := pty.Open()
					if err != nil {
						t.Fatal(err)
					}
					defer master.Close()
					defer terminal.Close()
					if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 30}); err != nil {
						t.Fatal(err)
					}
					go func() { _, _ = io.Copy(io.Discard, master) }()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					type completed struct {
						outcome Outcome
						err     error
					}
					result := make(chan completed, 1)
					inputFailure := errors.New("terminal input failed")
					input := &faultingTerminalReader{File: terminal, failure: inputFailure}
					if termination == "input-error-with-cancel" {
						input.failure = errors.Join(inputFailure, context.Canceled)
					}
					go func() { outcome, err := Run(ctx, model, input, terminal); result <- completed{outcome, err} }()
					go func() { time.Sleep(100 * time.Millisecond); _, _ = io.WriteString(master, "y") }()
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("save did not begin")
					}
					switch termination {
					case "input-error", "input-error-with-cancel":
						input.fail.Store(true)
						if _, err := io.WriteString(master, "?"); err != nil {
							t.Fatal(err)
						}
					case "context":
						cancel()
					case "SIGTERM":
						if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
							t.Fatal(err)
						}
					case "SIGINT":
						if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
							t.Fatal(err)
						}
					case "Ctrl+C":
						if _, err := io.WriteString(master, "\x03"); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case result := <-result:
						close(release)
						t.Fatalf("runtime returned before settlement: %v", result.err)
					case <-time.After(100 * time.Millisecond):
					}
					close(release)
					select {
					case result := <-result:
						if result.outcome.Cancelled {
							t.Fatal("transaction became ordinary cancellation")
						}
						if state == "success" {
							if strings.HasPrefix(termination, "input-error") {
								var transaction *profilerepo.OutcomeError
								if !errors.Is(result.err, inputFailure) || !errors.As(result.err, &transaction) || transaction.Outcome.State != profilerepo.Committed || transaction.Outcome.RecoveryRequired {
									t.Fatalf("lost input failure or invented uncertainty after commit: %#v %v", transaction, result.err)
								}
								return
							}
							if result.err != nil || !result.outcome.Create || result.outcome.Path != "saved" {
								t.Fatalf("lost committed success: %#v %v", result.outcome, result.err)
							}
							return
						}
						var outcome *profilerepo.OutcomeError
						if !errors.As(result.err, &outcome) || outcome.Outcome.State != profilerepo.State(state) {
							t.Fatalf("lost terminal state %s: %v", state, result.err)
						}
						if strings.Contains(result.err.Error(), "creation cancelled") {
							t.Fatal("false cancellation")
						}
					case <-time.After(3 * time.Second):
						t.Fatal("settlement did not return")
					}
				})
			}
		}
	}
}

func TestClosedRuntimeGatePreventsLateSave(t *testing.T) {
	_, registry := newBuilderFixture(t)
	gate := &saveRuntime{}
	if gate.settle() != nil {
		t.Fatal("empty gate had an attempt")
	}
	called := false
	result := gate.execute(context.Background(), registry.NewDraft(), func(context.Context, category.Draft) (string, error) { called = true; return "", nil })
	if called || !errors.Is(result.err, context.Canceled) {
		t.Fatal("late command started storage after terminal shutdown")
	}
}

// Keep a real terminal descriptor so the production runtime owns terminal setup.
// A completed read releases the injected error only after the save has started.
type faultingTerminalReader struct {
	*os.File
	fail    atomic.Bool
	failure error
}

func (r *faultingTerminalReader) Read(p []byte) (int, error) {
	n, err := r.File.Read(p)
	if r.fail.Load() {
		return 0, r.failure
	}
	return n, err
}

func TestHandledSaveFailureDoesNotMaskLaterTerminalFailure(t *testing.T) {
	for _, failure := range []error{profilerepo.ErrConflict, errors.New("save rejected")} {
		t.Run(failure.Error(), func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			model := newLoadedSkillsModel(t, "runtime", registry.NewDraft(), registry, binding, nil)
			var saves atomic.Int32
			model = model.WithSaver(func(context.Context, category.Draft) (string, error) {
				saves.Add(1)
				return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.NotCommitted}, Err: failure}
			})
			model.overviewCursor = 1
			model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 30}); err != nil {
				t.Fatal(err)
			}
			capture := &ptyCapture{}
			go func() {
				buffer := make([]byte, 4096)
				for {
					n, err := master.Read(buffer)
					capture.Write(buffer[:n])
					if err != nil {
						return
					}
				}
			}()
			inputFailure := errors.New("later terminal failure")
			input := &faultingTerminalReader{File: terminal, failure: inputFailure}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := Run(ctx, model, input, terminal); result <- err }()
			waitForPTYOutput(t, capture, "Confirm: Create an empty Profile?")
			writePTY(t, master, "y")
			waitForPTYOutput(t, capture, "Error: Profile could not be saved:")
			input.fail.Store(true)
			writePTY(t, master, "?")
			select {
			case err := <-result:
				if !errors.Is(err, inputFailure) || errors.Is(err, failure) || saves.Load() != 1 {
					t.Fatalf("old failure masked current terminal error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("terminal failure did not stop the runtime")
			}
		})
	}
}

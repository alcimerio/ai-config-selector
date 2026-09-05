//go:build darwin || linux

package builder

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
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
	for _, termination := range []string{"context", "SIGTERM", "SIGINT", "Ctrl+C"} {
		for _, state := range []string{"success", "committed", "unknown"} {
			t.Run(termination+"/"+state, func(t *testing.T) {
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
				go func() { outcome, err := Run(ctx, model, terminal, terminal); result <- completed{outcome, err} }()
				go func() { time.Sleep(100 * time.Millisecond); _, _ = io.WriteString(master, "y") }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("save did not begin")
				}
				switch termination {
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

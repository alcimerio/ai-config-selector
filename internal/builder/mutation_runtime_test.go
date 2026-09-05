//go:build darwin || linux

package builder

import (
	"context"
	"errors"
	"github.com/creack/pty"
	"io"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// Cancellation of the program must not outpace an already executing repository
// call. The saver deliberately ignores cancellation during settlement.
func TestMutationRuntimeCancellationWaitsForCommitOutcome(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.Committed, profilerepo.Unknown} {
		t.Run(string(state), func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			model := newLoadedSkillsModel(t, "runtime", registry.NewDraft(), registry, binding, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			model = model.WithSaver(func(context.Context, category.Draft) (string, error) {
				close(entered)
				<-release
				return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: state, RecoveryRequired: true}, Err: context.Canceled}
			})
			model.overviewCursor = 1
			model = update(t, model, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
			// Input selects the already displayed empty-Profile confirmation.
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
			result := make(chan error, 1)
			go func() { _, err := Run(ctx, model, terminal, terminal); result <- err }()
			go func() { time.Sleep(100 * time.Millisecond); _, _ = io.WriteString(master, "y") }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("save did not begin")
			}
			cancel()
			select {
			case err := <-result:
				close(release)
				t.Fatalf("runtime returned before settlement: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-result:
				var outcome *profilerepo.OutcomeError
				if !errors.As(err, &outcome) || outcome.Outcome.State != state {
					t.Fatalf("lost terminal state %s: %v", state, err)
				}
				if strings.Contains(err.Error(), "creation cancelled") {
					t.Fatal("false cancellation")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("settlement did not return")
			}
		})
	}
}

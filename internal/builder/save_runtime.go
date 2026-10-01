package builder

import (
	"context"
	"errors"
	"fmt"
	"sync"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// saveRuntime closes the gap between terminal cancellation and an in-flight
// transaction's settlement. It is not a persistence/recovery mechanism: the
// repository alone decides commitment. A closed gate prevents late tea commands
// from starting a transaction after the terminal runtime has already returned.
type saveRuntime struct {
	mutex   sync.Mutex
	closed  bool
	current *runtimeAttempt
}
type runtimeAttempt struct {
	cancel context.CancelFunc
	done   chan struct{}
	result saveCompletedMsg
}

func (r *saveRuntime) execute(ctx context.Context, draft category.Draft, save SaveFunc) (result saveCompletedMsg) {
	r.mutex.Lock()
	if r.closed {
		r.mutex.Unlock()
		return saveCompletedMsg{draft: draft, err: context.Canceled}
	}
	attemptContext, cancel := context.WithCancel(ctx)
	attempt := &runtimeAttempt{cancel: cancel, done: make(chan struct{})}
	r.current = attempt
	r.mutex.Unlock()
	// Keep a conservative result even if the callback never returns normally.
	// Settlement must not fabricate a successful transaction result.
	result = saveCompletedMsg{draft: draft, attempt: attempt, err: &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.Unknown, RecoveryRequired: true}, Err: errors.New("save ended without a repository outcome")}}
	defer func() { cancel(); attempt.result = result; close(attempt.done) }()
	result.path, result.err = saveWithRecovery(attemptContext, draft, save)
	return result
}

// A callback panic must return through the model's fatal completion and orderly
// Quit. Bubble Tea's panic shutdown closes the cancellable reader without
// waiting for its read loop. The repository supplied no outcome, so publication
// and cleanup are unknown; neither retry nor cancellation is safe to report.
func saveWithRecovery(ctx context.Context, draft category.Draft, save SaveFunc) (path string, err error) {
	returned := false
	defer func() {
		if !returned {
			// Do not inspect or format the payload: it can contain private data,
			// implement a panicking String method, or be nil.
			_ = recover()
			path = ""
			err = &profilerepo.OutcomeError{
				Outcome: profilerepo.Outcome{State: profilerepo.Unknown, RecoveryRequired: true},
				Err:     fmt.Errorf("save ended without a repository outcome: %w", tea.ErrProgramPanic),
			}
		}
	}()
	path, err = save(ctx, draft)
	returned = true
	return path, err
}

// Once the model has handled an ordinary noncommitted failure, it owns the
// failure screen and any later retry/reload/cancel decision. Shutdown must not
// resurrect that obsolete attempt. Unobserved and uncertain outcomes stay held.
func (r *saveRuntime) acknowledge(result saveCompletedMsg) {
	if result.err == nil || result.attempt == nil {
		return
	}
	var transaction *profilerepo.OutcomeError
	if errors.As(result.err, &transaction) && (transaction.Outcome.State != profilerepo.NotCommitted || transaction.Outcome.RecoveryRequired) {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.current == result.attempt {
		r.current = nil
	}
}

func (r *saveRuntime) stop() *runtimeAttempt {
	r.mutex.Lock()
	r.closed = true
	attempt := r.current
	r.mutex.Unlock()
	if attempt == nil {
		return nil
	}
	attempt.cancel()
	return attempt
}

func (r *saveRuntime) settle() *saveCompletedMsg {
	attempt := r.stop()
	if attempt == nil {
		return nil
	}
	<-attempt.done
	return &attempt.result
}

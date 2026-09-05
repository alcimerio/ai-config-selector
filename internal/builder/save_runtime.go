package builder

import (
	"context"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"sync"

	"github.com/alcimerio/ai-config-selector/internal/category"
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
	// A saver panic remains Bubble Tea's existing panic path; completion still
	// releases the waiter. It does not fabricate a successful transaction result.
	result = saveCompletedMsg{draft: draft, err: &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.Unknown, RecoveryRequired: true}, Err: errors.New("save ended without a repository outcome")}}
	defer func() { cancel(); attempt.result = result; close(attempt.done) }()
	result.path, result.err = save(attemptContext, draft)
	return result
}

func (r *saveRuntime) settle() *saveCompletedMsg {
	r.mutex.Lock()
	r.closed = true
	attempt := r.current
	r.mutex.Unlock()
	if attempt == nil {
		return nil
	}
	attempt.cancel()
	<-attempt.done
	return &attempt.result
}

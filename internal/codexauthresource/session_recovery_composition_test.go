package codexauthresource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const compositionSessionID = "session-composition"
const compositionChallenge = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newCompositionStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	locks, quarantine := filepath.Join(root, "locks"), filepath.Join(root, "quarantine")
	for _, path := range []string{locks, quarantine} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(locks, quarantine)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func createCompositionMarker(t *testing.T, store *Store, name CredentialRef, phase quarantinePhase) {
	t.Helper()
	if err := store.markers.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: name, SessionID: compositionSessionID,
		Phase: phase, ProofChallenge: compositionChallenge,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireRecoveryBySessionRejectsMissingAndAmbiguousAuthority(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		binding, exists, err := newCompositionStore(t).AcquireRecoveryBySession(context.Background(), compositionSessionID)
		if err != nil || exists || binding != nil {
			t.Fatalf("missing authority = (%v, %t, %v)", binding, exists, err)
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		store := newCompositionStore(t)
		createCompositionMarker(t, store, "one", quarantineRecoverable)
		createCompositionMarker(t, store, "two", quarantineRecoverable)
		binding, exists, err := store.AcquireRecoveryBySession(context.Background(), compositionSessionID)
		if binding != nil || exists || !errors.Is(err, ErrBindingQuarantined) {
			t.Fatalf("ambiguous authority = (%v, %t, %v)", binding, exists, err)
		}
	})
}

func TestAcquireRecoveryBySessionContentionHonorsBoundedContext(t *testing.T) {
	store := newCompositionStore(t)
	createCompositionMarker(t, store, "work", quarantineRecoverable)
	held, err := store.AcquireRecovery(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	deadline, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	if binding, exists, err := store.AcquireRecoveryBySession(deadline, compositionSessionID); binding != nil || !exists || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline contention = (%v, %t, %v)", binding, exists, err)
	} else if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("deadline contention was not bounded: %s", elapsed)
	}

	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if binding, exists, err := store.AcquireRecoveryBySession(cancelled, compositionSessionID); binding != nil || exists || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled contention = (%v, %t, %v)", binding, exists, err)
	}
}

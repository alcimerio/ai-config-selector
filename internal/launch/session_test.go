package launch

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPartialCleanupFailureKeepsTheExternalSessionLeaseIdentityLocked(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	session, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(session.RootDir, "protected"), 0o700)
		if session.guard != nil {
			closeLockedFile(session.guard)
			session.guard = nil
		}
		_ = os.RemoveAll(session.RootDir)
	})
	protected := filepath.Join(session.RootDir, "protected")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "fixture"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(protected, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := session.Remove(); err == nil {
		t.Fatal("Session cleanup unexpectedly succeeded")
	}
	guardPath := filepath.Join(sessionsDirectory+".leases", filepath.Base(session.RootDir)+".lock")
	guard, err := openLockedFile(guardPath, true)
	if err == nil {
		closeLockedFile(guard)
		t.Fatal("partial cleanup replaced the Session lease identity")
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("failed cleanup lease error = %v, want EWOULDBLOCK", err)
	}

	concurrent, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatalf("later launch treated a failed cleanup as abandoned: %v", err)
	}
	if err := concurrent.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RootDir); err != nil {
		t.Fatalf("later launch removed the Session from a failed cleanup: %v", err)
	}
}

func TestRecoveryRemovesTransientExternalLeaseForActiveLegacySession(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	legacySession := filepath.Join(sessionsDirectory, "session-legacy")
	if err := os.MkdirAll(legacySession, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyGuard, err := openLockedFile(filepath.Join(legacySession, legacySessionLeaseFile), false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLockedFile(legacyGuard)

	current, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacySession); err != nil {
		t.Fatalf("recovery removed the active legacy Session: %v", err)
	}
	transientGuard := sessionLeasePath(sessionsDirectory, legacySession)
	if _, err := os.Stat(transientGuard); !os.IsNotExist(err) {
		t.Fatalf("active legacy recovery left an external lease artifact: %v", err)
	}
}

func TestAwaitRetainedSessionCleanupBoundsPendingCleanupAndKeepsLease(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	session, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	cleanupDone := make(chan struct{})
	retained, err := RetainSessionUntilProcessDone(pendingSessionCleanupProcess{cleanupDone: cleanupDone}, session)
	if err != nil {
		t.Fatal(err)
	}
	process := retained.(*sessionProcess)
	timeout := make(chan time.Time, 1)
	process.cleanupTimeout = func() <-chan time.Time { return timeout }

	result := make(chan error, 1)
	go func() { result <- AwaitRetainedSessionCleanup(retained) }()
	timeout <- time.Now()
	var sandboxErr *SandboxError
	select {
	case err := <-result:
		if !errors.As(err, &sandboxErr) || sandboxErr.Category != SandboxProcessWaitFailed {
			t.Fatalf("bounded cleanup wait = %v, want safe process wait failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup wait did not respect its bounded timeout")
	}

	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.RootDir); err != nil {
		t.Fatalf("bounded cleanup wait released pending Session: %v", err)
	}
	close(cleanupDone)
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(session.RootDir); os.IsNotExist(err) {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Session remained after deferred cleanup completed")
		}
		time.Sleep(time.Millisecond)
	}
}

type pendingSessionCleanupProcess struct {
	cleanupDone <-chan struct{}
}

func (pendingSessionCleanupProcess) Start() error           { return nil }
func (pendingSessionCleanupProcess) Wait() error            { return nil }
func (pendingSessionCleanupProcess) Signal(os.Signal) error { return nil }
func (process pendingSessionCleanupProcess) CleanupDone() <-chan struct{} {
	return process.cleanupDone
}

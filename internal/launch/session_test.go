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

func TestRecoverSessionRejectsActiveLeaseAndOwnsAbandonedSession(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	created, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	sessionID := filepath.Base(created.RootDir)
	if recovered, exists, err := RecoverSession(sessionsDirectory, sessionID); recovered != nil || !exists || !errors.Is(err, ErrSessionStillActive) {
		t.Fatalf("active recovery = (%#v, %v, %v)", recovered, exists, err)
	}

	closeLockedFile(created.guard)
	created.guard = nil
	recovered, exists, err := RecoverSession(sessionsDirectory, sessionID)
	if err != nil || !exists || recovered == nil {
		t.Fatalf("abandoned recovery = (%#v, %v, %v)", recovered, exists, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created.RootDir); !os.IsNotExist(err) {
		t.Fatalf("recovered Session remains: %v", err)
	}
}

func TestRecoverPreparedSessionOwnsAbandonedUnprotectedSessionButRejectsActiveLease(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	created, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := filepath.Base(created.RootDir)
	if recovered, exists, err := RecoverPreparedSession(sessionsDirectory, sessionID); recovered != nil || !exists || !errors.Is(err, ErrSessionStillActive) {
		t.Fatalf("active prepared recovery = (%#v, %v, %v)", recovered, exists, err)
	}

	closeLockedFile(created.guard)
	created.guard = nil
	recovered, exists, err := RecoverPreparedSession(sessionsDirectory, sessionID)
	if err != nil || !exists || recovered == nil {
		t.Fatalf("abandoned prepared recovery = (%#v, %v, %v)", recovered, exists, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created.RootDir); !os.IsNotExist(err) {
		t.Fatalf("recovered prepared Session remains: %v", err)
	}
}

func TestRecoverPreparedSessionRejectsMalformedUnprotectedSession(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	for _, directory := range []string{sessionsDirectory, sessionLeasesDirectory(sessionsDirectory)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sessionsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessionLeasesDirectory(sessionsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("missing lease", func(t *testing.T) {
		sessionID := "session-missing-lease"
		if err := os.Mkdir(filepath.Join(sessionsDirectory, sessionID), 0o700); err != nil {
			t.Fatal(err)
		}
		if recovered, _, err := RecoverPreparedSession(sessionsDirectory, sessionID); recovered != nil || err == nil {
			t.Fatalf("missing-lease recovery = (%#v, %v)", recovered, err)
		}
	})

	t.Run("symlink root", func(t *testing.T) {
		sessionID := "session-symlink"
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(sessionsDirectory, sessionID)); err != nil {
			t.Fatal(err)
		}
		if recovered, _, err := RecoverPreparedSession(sessionsDirectory, sessionID); recovered != nil || err == nil {
			t.Fatalf("symlink-root recovery = (%#v, %v)", recovered, err)
		}
	})
}

func TestRecoveryProtectionSurvivesStartupCleanupUntilExplicitRecovery(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	created, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}

	concurrent, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := concurrent.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created.RootDir); err != nil {
		t.Fatalf("startup cleanup removed recovery-owned Session: %v", err)
	}

	recovered, exists, err := RecoverSession(sessionsDirectory, filepath.Base(created.RootDir))
	if err != nil || !exists || recovered == nil {
		t.Fatalf("protected recovery = (%#v, %v, %v)", recovered, exists, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
}

func TestPreserveForRecoveryRejectsUnprotectedSession(t *testing.T) {
	created, err := CreateSession(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	if err := created.PreserveForRecovery(); err == nil {
		t.Fatal("unprotected Session was preserved for recovery")
	}
}

func TestCreateSessionRejectsSymlinkDirectoriesWithoutChangingTargets(t *testing.T) {
	t.Run("Sessions directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "sessions")); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateSession(filepath.Join(root, "sessions")); err == nil {
			t.Fatal("symlink Sessions directory was accepted")
		}
		assertDirectoryMode(t, target, 0o755)
	})
	t.Run("lease directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		sessionsDirectory := filepath.Join(root, "sessions")
		if err := os.Mkdir(sessionsDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, sessionLeasesDirectory(sessionsDirectory)); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateSession(sessionsDirectory); err == nil {
			t.Fatal("symlink Session leases directory was accepted")
		}
		assertDirectoryMode(t, target, 0o755)
	})
}

func TestOpenLockedFileRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "lease.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openLockedFile(link, false); err == nil {
		closeLockedFile(file)
		t.Fatal("symlink lock was accepted")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode changed to %o", info.Mode().Perm())
	}
}

func assertDirectoryMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("directory mode = %o, want %o", info.Mode().Perm(), want)
	}
}

func TestRecoverSessionTreatsMissingSessionAsAlreadyRemoved(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessionsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if recovered, exists, err := RecoverSession(sessionsDirectory, "session-missing"); recovered != nil || exists || err != nil {
		t.Fatalf("missing recovery = (%#v, %v, %v)", recovered, exists, err)
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

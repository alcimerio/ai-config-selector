package launch

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
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

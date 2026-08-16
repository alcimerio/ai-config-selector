package launch

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCleanupFailureKeepsSessionLeasedUntilItsOwnerStops(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	session, err := CreateSession(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(session.RootDir, 0o700)
		if session.guard != nil {
			closeLockedFile(session.guard)
			session.guard = nil
		}
		_ = os.RemoveAll(session.RootDir)
	})
	if err := os.WriteFile(filepath.Join(session.RootDir, "protected"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(session.RootDir, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := session.Remove(); err == nil {
		t.Fatal("Session cleanup unexpectedly succeeded")
	}
	guard, err := openLockedFile(filepath.Join(session.RootDir, sessionLeaseFile), true)
	if err == nil {
		closeLockedFile(guard)
		t.Fatal("failed cleanup released the Session lease")
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

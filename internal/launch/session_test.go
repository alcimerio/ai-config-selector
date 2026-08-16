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

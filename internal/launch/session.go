package launch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	sessionDirectoryPrefix = "session-"
	sessionLeaseFile       = ".active.lock"
)

// SessionLease owns one ephemeral Session directory until Remove is called.
// A process-held file lock lets a later ACS startup distinguish an active
// Session from one abandoned by a terminated process.
type SessionLease struct {
	RootDir string
	guard   *os.File
}

// CreateSession removes abandoned Sessions and creates a leased Session while
// preserving Sessions held by concurrent ACS processes.
func CreateSession(sessionsDirectory string) (*SessionLease, error) {
	if err := os.MkdirAll(sessionsDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create ACS Sessions directory: %w", err)
	}
	if err := os.Chmod(sessionsDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("secure ACS Sessions directory: %w", err)
	}

	coordinator, err := openLockedFile(sessionsDirectory+".lock", false)
	if err != nil {
		return nil, fmt.Errorf("coordinate ACS Session startup: %w", err)
	}
	defer closeLockedFile(coordinator)

	if err := removeAbandonedSessions(sessionsDirectory); err != nil {
		return nil, err
	}
	rootDir, err := os.MkdirTemp(sessionsDirectory, sessionDirectoryPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("create ACS Session: %w", err)
	}
	guard, err := openLockedFile(filepath.Join(rootDir, sessionLeaseFile), false)
	if err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("lease ACS Session: %w", err)
	}
	return &SessionLease{RootDir: rootDir, guard: guard}, nil
}

// Remove releases and deletes the leased Session.
func (session *SessionLease) Remove() error {
	if session.guard != nil {
		closeLockedFile(session.guard)
		session.guard = nil
	}
	if err := os.RemoveAll(session.RootDir); err != nil {
		return errors.New("delete ACS Session: cleanup failed")
	}
	return nil
}

func removeAbandonedSessions(sessionsDirectory string) error {
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil {
		return fmt.Errorf("inspect ACS Sessions directory: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), sessionDirectoryPrefix) {
			continue
		}
		sessionPath := filepath.Join(sessionsDirectory, entry.Name())
		if !entry.IsDir() {
			if err := os.RemoveAll(sessionPath); err != nil {
				return errors.New("delete abandoned ACS Session: cleanup failed")
			}
			continue
		}

		guard, err := openLockedFile(filepath.Join(sessionPath, sessionLeaseFile), true)
		if os.IsNotExist(err) {
			continue
		}
		if errors.Is(err, syscall.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect abandoned ACS Session lease: %w", err)
		}
		if err := os.RemoveAll(sessionPath); err != nil {
			closeLockedFile(guard)
			return errors.New("delete abandoned ACS Session: cleanup failed")
		}
		closeLockedFile(guard)
	}
	return nil
}

func openLockedFile(path string, nonblocking bool) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	operation := syscall.LOCK_EX
	if nonblocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func closeLockedFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

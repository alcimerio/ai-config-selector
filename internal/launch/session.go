package launch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	sessionDirectoryPrefix = "session-"
	legacySessionLeaseFile = ".active.lock"
	sessionLeaseSuffix     = ".lock"
	sessionLeasesSuffix    = ".leases"
)

// SessionLease owns one ephemeral Session directory until Remove is called.
// A process-held file lock lets a later ACS startup distinguish an active
// Session from one abandoned by a terminated process.
type SessionLease struct {
	RootDir         string
	guard           *os.File
	guardPath       string
	mutex           sync.Mutex
	references      int
	removeRequested bool
	cleanupErr      error
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
	if err := os.MkdirAll(sessionLeasesDirectory(sessionsDirectory), 0o700); err != nil {
		return nil, fmt.Errorf("create ACS Session leases directory: %w", err)
	}
	if err := os.Chmod(sessionLeasesDirectory(sessionsDirectory), 0o700); err != nil {
		return nil, fmt.Errorf("secure ACS Session leases directory: %w", err)
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
	guardPath := sessionLeasePath(sessionsDirectory, rootDir)
	guard, err := openLockedFile(guardPath, false)
	if err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("lease ACS Session: %w", err)
	}
	return &SessionLease{RootDir: rootDir, guard: guard, guardPath: guardPath, references: 1}, nil
}

// Remove releases the caller's ownership and deletes the leased Session after
// every prepared process has proved that its contained process tree is gone.
func (session *SessionLease) Remove() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.removeRequested {
		return session.cleanupErr
	}
	session.removeRequested = true
	session.references--
	if session.references > 0 {
		return nil
	}
	return session.removeLocked()
}

func (session *SessionLease) retain() (func() error, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.removeRequested || session.references <= 0 {
		return nil, errors.New("retain ACS Session: lease has already been released")
	}
	session.references++
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() { releaseErr = session.releaseReference() })
		return releaseErr
	}, nil
}

func (session *SessionLease) releaseReference() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	session.references--
	if session.references > 0 || !session.removeRequested {
		return nil
	}
	return session.removeLocked()
}

func (session *SessionLease) removeLocked() error {
	// Keep the lease locked until removal succeeds. A failed cleanup must remain
	// owned by this ACS process so concurrent abandoned-session recovery cannot
	// remove a Session whose contained process cleanup is still in progress.
	if err := os.RemoveAll(session.RootDir); err != nil {
		session.cleanupErr = errors.New("delete ACS Session: cleanup failed")
		return session.cleanupErr
	}
	if session.guard != nil {
		closeLockedFile(session.guard)
		session.guard = nil
	}
	if err := os.Remove(session.guardPath); err != nil && !os.IsNotExist(err) {
		session.cleanupErr = errors.New("delete ACS Session: cleanup failed")
		return session.cleanupErr
	}
	session.cleanupErr = nil
	return nil
}

// RetainSessionUntilProcessDone holds a Session lease for a prepared process.
// If startup or Wait transfers bounded cleanup to a backend quarantine, the
// Session remains leased until CleanupDone reports stable process-tree death.
func RetainSessionUntilProcessDone(process Process, session *SessionLease) (Process, error) {
	if process == nil || session == nil {
		return process, nil
	}
	release, err := session.retain()
	if err != nil {
		return nil, err
	}
	var cleanupDone <-chan struct{}
	if notifier, ok := process.(ProcessCleanup); ok {
		cleanupDone = notifier.CleanupDone()
	}
	return &sessionProcess{process: process, cleanupDone: cleanupDone, release: release}, nil
}

type sessionProcess struct {
	process     Process
	cleanupDone <-chan struct{}
	release     func() error
	releaseOnce sync.Once
}

func (process *sessionProcess) Start() error {
	err := process.process.Start()
	if err == nil {
		return nil
	}
	return errors.Join(err, process.releaseAfterCleanup())
}

func (process *sessionProcess) Wait() error {
	return errors.Join(process.process.Wait(), process.releaseAfterCleanup())
}

func (process *sessionProcess) Signal(signal os.Signal) error {
	return process.process.Signal(signal)
}

func (process *sessionProcess) CleanupDone() <-chan struct{} {
	return process.cleanupDone
}

func (process *sessionProcess) releaseAfterCleanup() error {
	if process.cleanupDone == nil {
		return process.releaseNow()
	}
	select {
	case <-process.cleanupDone:
		return process.releaseNow()
	default:
		process.releaseOnce.Do(func() {
			go func() {
				<-process.cleanupDone
				_ = process.release()
			}()
		})
		return nil
	}
}

func (process *sessionProcess) releaseNow() error {
	var err error
	process.releaseOnce.Do(func() { err = process.release() })
	return err
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

		guardPath := sessionLeasePath(sessionsDirectory, sessionPath)
		guard, err := openLockedFile(guardPath, true)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect abandoned ACS Session lease: %w", err)
		}
		legacyGuard, err := openLockedFile(filepath.Join(sessionPath, legacySessionLeaseFile), true)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			closeLockedFile(guard)
			continue
		}
		if err != nil && !os.IsNotExist(err) {
			closeLockedFile(guard)
			return fmt.Errorf("inspect abandoned ACS Session lease: %w", err)
		}
		if err := os.RemoveAll(sessionPath); err != nil {
			if legacyGuard != nil {
				closeLockedFile(legacyGuard)
			}
			closeLockedFile(guard)
			return errors.New("delete abandoned ACS Session: cleanup failed")
		}
		if legacyGuard != nil {
			closeLockedFile(legacyGuard)
		}
		closeLockedFile(guard)
		if err := os.Remove(guardPath); err != nil && !os.IsNotExist(err) {
			return errors.New("delete abandoned ACS Session: cleanup failed")
		}
	}
	return nil
}

func sessionLeasesDirectory(sessionsDirectory string) string {
	return sessionsDirectory + sessionLeasesSuffix
}

func sessionLeasePath(sessionsDirectory, sessionRoot string) string {
	return filepath.Join(sessionLeasesDirectory(sessionsDirectory), filepath.Base(sessionRoot)+sessionLeaseSuffix)
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

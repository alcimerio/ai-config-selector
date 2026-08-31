package launch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	sessionDirectoryPrefix = "session-"
	legacySessionLeaseFile = ".active.lock"
	sessionLeaseSuffix     = ".lock"
	sessionRecoverySuffix  = ".recovery"
	sessionLeasesSuffix    = ".leases"
	sessionCleanupWaitTime = 5 * time.Second
)

var ErrSessionStillActive = errors.New("ACS Session is still active")

// SessionLease owns one ephemeral Session directory until Remove is called.
// A process-held file lock lets a later ACS startup distinguish an active
// Session from one abandoned by a terminated process.
type SessionLease struct {
	RootDir           string
	guard             *os.File
	guardPath         string
	recoveryPath      string
	recoveryProtected bool
	mutex             sync.Mutex
	references        int
	removeRequested   bool
	cleanupErr        error
}

// RecoveredSessionLease owns an abandoned Session while a higher-level module
// completes recovery. Holding the external guard prevents concurrent startup
// cleanup from deleting the Session during that decision.
type RecoveredSessionLease struct {
	RootDir           string
	sessionsDirectory string
	guard             *os.File
	guardPath         string
	recoveryPath      string
}

// RecoverSession acquires an abandoned Session by its non-secret directory
// identifier. An active Session is never taken over.
func RecoverSession(sessionsDirectory, sessionID string) (*RecoveredSessionLease, bool, error) {
	return recoverSession(sessionsDirectory, sessionID, false)
}

// RecoverPreparedSession acquires an abandoned Session for a higher-level
// prepared binding. Prepared bindings may have published their durable marker
// immediately before recovery protection, so this seam alone accepts a valid
// inactive Session without that protection. Active and malformed Sessions
// remain unavailable.
func RecoverPreparedSession(sessionsDirectory, sessionID string) (*RecoveredSessionLease, bool, error) {
	return recoverSession(sessionsDirectory, sessionID, true)
}

func recoverSession(
	sessionsDirectory string,
	sessionID string,
	allowUnprotected bool,
) (*RecoveredSessionLease, bool, error) {
	if filepath.Base(sessionID) != sessionID || !strings.HasPrefix(sessionID, sessionDirectoryPrefix) || len(sessionID) > 200 {
		return nil, false, errors.New("recover ACS Session: invalid identifier")
	}
	if _, err := os.Lstat(sessionsDirectory); os.IsNotExist(err) {
		return nil, false, nil
	}
	if err := validatePrivateSessionDirectory(sessionsDirectory); err != nil {
		return nil, false, errors.New("recover ACS Session: invalid Sessions directory")
	}
	root := filepath.Join(sessionsDirectory, sessionID)
	if _, err := os.Lstat(sessionLeasesDirectory(sessionsDirectory)); os.IsNotExist(err) {
		if _, rootErr := os.Lstat(root); os.IsNotExist(rootErr) {
			return nil, false, nil
		}
	}
	if err := validatePrivateSessionDirectory(sessionLeasesDirectory(sessionsDirectory)); err != nil {
		return nil, false, errors.New("recover ACS Session: invalid Session leases directory")
	}
	coordinator, err := openLockedFile(sessionsDirectory+".lock", false)
	if err != nil {
		return nil, false, errors.New("recover ACS Session: coordination failed")
	}
	defer closeLockedFile(coordinator)

	recoveryPath := sessionRecoveryPath(sessionsDirectory, root)
	protected, err := validRecoveryProtection(recoveryPath)
	if err != nil {
		return nil, false, errors.New("recover ACS Session: invalid recovery protection")
	}
	rootInfo, err := os.Lstat(root)
	if os.IsNotExist(err) {
		if !protected {
			return nil, false, nil
		}
		guardPath := sessionLeasePath(sessionsDirectory, root)
		guard, lockErr := openExistingLockedFile(guardPath, true)
		if errors.Is(lockErr, os.ErrNotExist) {
			if err := os.Remove(recoveryPath); err != nil && !os.IsNotExist(err) {
				return nil, false, errors.New("recover ACS Session: cleanup failed")
			}
			if err := syncSessionLeaseDirectory(sessionsDirectory); err != nil {
				return nil, false, errors.New("recover ACS Session: cleanup failed")
			}
			return nil, false, nil
		}
		if errors.Is(lockErr, syscall.EWOULDBLOCK) {
			return nil, true, ErrSessionStillActive
		}
		if lockErr != nil {
			return nil, false, errors.New("recover ACS Session: lease failed")
		}
		defer closeLockedFile(guard)
		if err := os.Remove(guardPath); err != nil && !os.IsNotExist(err) {
			return nil, false, errors.New("recover ACS Session: cleanup failed")
		}
		if err := os.Remove(recoveryPath); err != nil && !os.IsNotExist(err) {
			return nil, false, errors.New("recover ACS Session: cleanup failed")
		}
		if err := syncSessionLeaseDirectory(sessionsDirectory); err != nil {
			return nil, false, errors.New("recover ACS Session: cleanup failed")
		}
		return nil, false, nil
	}
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("recover ACS Session: invalid Session")
	}
	if !protected && !allowUnprotected {
		return nil, false, errors.New("recover ACS Session: Session is not recovery protected")
	}
	guardPath := sessionLeasePath(sessionsDirectory, root)
	guard, err := openExistingLockedFile(guardPath, true)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil, true, ErrSessionStillActive
	}
	if err != nil {
		return nil, false, errors.New("recover ACS Session: lease failed")
	}
	return &RecoveredSessionLease{
		RootDir: root, sessionsDirectory: sessionsDirectory, guard: guard,
		guardPath: guardPath, recoveryPath: recoveryPath,
	}, true, nil
}

// Preserve releases recovery ownership without deleting the Session.
func (session *RecoveredSessionLease) Preserve() {
	if session == nil || session.guard == nil {
		return
	}
	closeLockedFile(session.guard)
	session.guard = nil
}

// Remove deletes the recovered Session while coordinating with new Session
// startup, then releases its external guard.
func (session *RecoveredSessionLease) Remove() error {
	if session == nil || session.guard == nil {
		return nil
	}
	coordinator, err := openLockedFile(session.sessionsDirectory+".lock", false)
	if err != nil {
		return errors.New("remove recovered ACS Session: coordination failed")
	}
	defer closeLockedFile(coordinator)
	if err := os.RemoveAll(session.RootDir); err != nil {
		return errors.New("remove recovered ACS Session: cleanup failed")
	}
	if err := os.Remove(session.guardPath); err != nil && !os.IsNotExist(err) {
		return errors.New("remove recovered ACS Session: cleanup failed")
	}
	if err := os.Remove(session.recoveryPath); err != nil && !os.IsNotExist(err) {
		return errors.New("remove recovered ACS Session: cleanup failed")
	}
	if err := syncSessionLeaseDirectory(session.sessionsDirectory); err != nil {
		return errors.New("remove recovered ACS Session: cleanup failed")
	}
	closeLockedFile(session.guard)
	session.guard = nil
	return nil
}

// CreateSession removes abandoned Sessions and creates a leased Session while
// preserving Sessions held by concurrent ACS processes.
func CreateSession(sessionsDirectory string) (*SessionLease, error) {
	if err := securePrivateSessionDirectory(sessionsDirectory); err != nil {
		return nil, fmt.Errorf("create ACS Sessions directory: %w", err)
	}
	if err := securePrivateSessionDirectory(sessionLeasesDirectory(sessionsDirectory)); err != nil {
		return nil, fmt.Errorf("create ACS Session leases directory: %w", err)
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
	return &SessionLease{
		RootDir: rootDir, guard: guard, guardPath: guardPath,
		recoveryPath: sessionRecoveryPath(sessionsDirectory, rootDir), references: 1,
	}, nil
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

// ProtectForRecovery durably marks a live Session as owned by a higher-level
// recovery workflow. Generic startup cleanup will not reclaim it until that
// workflow removes the protection under the Session lease.
func (session *SessionLease) ProtectForRecovery() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.guard == nil || session.removeRequested || session.references <= 0 {
		return errors.New("protect ACS Session for recovery: Session is not active")
	}
	if session.recoveryProtected {
		return nil
	}
	if err := createRecoveryProtection(session.recoveryPath); err != nil {
		return errors.New("protect ACS Session for recovery: persistence failed")
	}
	session.recoveryProtected = true
	return nil
}

// PreserveForRecovery transfers an inactive Session from the live in-process
// lease to durable recovery ownership without deleting its files. It is valid
// only after every retained process reference has settled.
func (session *SessionLease) PreserveForRecovery() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.guard == nil || !session.recoveryProtected || session.references > 1 || (!session.removeRequested && session.references != 1) || (session.removeRequested && session.references != 0) {
		return errors.New("preserve ACS Session for recovery: Session is still active")
	}
	closeLockedFile(session.guard)
	session.guard = nil
	session.references = 0
	session.removeRequested = true
	return nil
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
	if err := os.Remove(session.guardPath); err != nil && !os.IsNotExist(err) {
		session.cleanupErr = errors.New("delete ACS Session: cleanup failed")
		return session.cleanupErr
	}
	if err := os.Remove(session.recoveryPath); err != nil && !os.IsNotExist(err) {
		session.cleanupErr = errors.New("delete ACS Session: cleanup failed")
		return session.cleanupErr
	}
	if err := syncDirectoryPath(filepath.Dir(session.guardPath)); err != nil {
		session.cleanupErr = errors.New("delete ACS Session: cleanup failed")
		return session.cleanupErr
	}
	if session.guard != nil {
		closeLockedFile(session.guard)
		session.guard = nil
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
	return &sessionProcess{
		process: process, cleanupDone: cleanupDone, release: release, releaseDone: make(chan struct{}),
		cleanupTimeout: func() <-chan time.Time { return time.After(sessionCleanupWaitTime) },
	}, nil
}

type sessionProcess struct {
	process                 Process
	cleanupDone             <-chan struct{}
	release                 func() error
	releaseOnce             sync.Once
	releaseAfterCleanupOnce sync.Once
	releaseDone             chan struct{}
	releaseErr              error
	cleanupTimeout          func() <-chan time.Time
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

// AwaitRetainedSessionCleanup waits a bounded amount for cleanup of a Session
// retained for a process. Callers must use it before reporting an ordinary
// target exit, because a cleanup failure takes precedence over that exit.
func AwaitRetainedSessionCleanup(process Process) error {
	retained, ok := process.(*sessionProcess)
	if !ok || retained.cleanupDone == nil {
		return nil
	}
	return retained.awaitCleanup()
}

func (process *sessionProcess) releaseAfterCleanup() error {
	if process.cleanupDone == nil {
		return process.releaseNow()
	}
	select {
	case <-process.cleanupDone:
		return process.releaseNow()
	default:
		process.releaseAfterCleanupOnce.Do(func() {
			go func() {
				<-process.cleanupDone
				_ = process.releaseNow()
			}()
		})
		return nil
	}
}

func (process *sessionProcess) awaitCleanup() error {
	timeout := process.cleanupTimeout
	if timeout == nil {
		timeout = func() <-chan time.Time { return time.After(sessionCleanupWaitTime) }
	}
	select {
	case <-process.cleanupDone:
		return process.releaseNow()
	case <-timeout():
		// Keep the Session retained after a bounded wait. The asynchronous
		// release still runs once cleanup is eventually proven complete.
		_ = process.releaseAfterCleanup()
		return sandboxError(SandboxProcessWaitFailed, nil)
	}
}

func (process *sessionProcess) releaseNow() error {
	process.releaseOnce.Do(func() {
		process.releaseErr = process.release()
		close(process.releaseDone)
	})
	<-process.releaseDone
	return process.releaseErr
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
		protected, err := validRecoveryProtection(sessionRecoveryPath(sessionsDirectory, sessionPath))
		if err != nil {
			return errors.New("inspect abandoned ACS Session recovery protection: invalid marker")
		}
		if protected {
			continue
		}
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
			// This process holds the startup coordinator and has proved no modern
			// lease owns guardPath. It was created solely to inspect a legacy
			// Session, so remove it before preserving the legacy lock. Keeping it
			// would leave a permanent external artifact once that older ACS exits.
			if err := os.Remove(guardPath); err != nil && !os.IsNotExist(err) {
				return errors.New("delete abandoned ACS Session: cleanup failed")
			}
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

func sessionRecoveryPath(sessionsDirectory, sessionRoot string) string {
	return filepath.Join(sessionLeasesDirectory(sessionsDirectory), filepath.Base(sessionRoot)+sessionRecoverySuffix)
}

func createRecoveryProtection(path string) error {
	descriptor, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return errors.New("create recovery protection")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDirectoryPath(filepath.Dir(path))
}

func validRecoveryProtection(path string) (bool, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return false, errors.New("inspect recovery protection")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		return false, errors.New("invalid recovery protection")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return false, errors.New("invalid recovery protection")
	}
	return true, nil
}

func syncSessionLeaseDirectory(sessionsDirectory string) error {
	return syncDirectoryPath(sessionLeasesDirectory(sessionsDirectory))
}

func syncDirectoryPath(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func securePrivateSessionDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory")
	}
	return os.Chmod(path, 0o700)
}

func validatePrivateSessionDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory")
	}
	return nil
}

func openLockedFile(path string, nonblocking bool) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open locked file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("invalid locked file")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("invalid locked file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
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

func openExistingLockedFile(path string, nonblocking bool) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open existing locked file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, errors.New("invalid existing locked file")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("invalid existing locked file")
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

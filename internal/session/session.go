// Package session owns the target-independent lifecycle of one ephemeral ACS
// Session and its synthetic filesystem.
package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// Materializer writes the resolved Profile contents into a synthetic Session
// home without performing target-specific verification or authentication.
type Materializer interface {
	Materialize(homeDirectory string) error
}

// Session owns a leased ephemeral root and the paths exposed to a contained
// process. Remove is idempotent.
type Session struct {
	lease              *launch.SessionLease
	sessionsDirectory  string
	homeDirectory      string
	temporaryDirectory string
	workingDirectory   string
}

// Create leases a new Session, creates its synthetic home and temporary
// directory, and materializes the resolved Profile into that home.
func Create(sessionsDirectory, workingDirectory string, materializer Materializer) (*Session, error) {
	lease, err := launch.CreateSession(sessionsDirectory)
	if err != nil {
		return nil, err
	}
	created := &Session{
		lease:              lease,
		sessionsDirectory:  filepath.Clean(sessionsDirectory),
		homeDirectory:      filepath.Join(lease.RootDir, "home"),
		temporaryDirectory: filepath.Join(lease.RootDir, "tmp"),
		workingDirectory:   filepath.Clean(workingDirectory),
	}
	cleanupFailure := func(cause error) (*Session, error) {
		return nil, errors.Join(cause, created.Remove())
	}
	for _, directory := range []string{
		created.homeDirectory,
		created.temporaryDirectory,
		filepath.Join(created.homeDirectory, ".config"),
		filepath.Join(created.homeDirectory, ".local"),
		filepath.Join(created.homeDirectory, ".local", "share"),
		filepath.Join(created.homeDirectory, ".cache"),
		filepath.Join(created.homeDirectory, ".local", "state"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return cleanupFailure(fmt.Errorf("prepare ACS Session filesystem: %w", err))
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return cleanupFailure(fmt.Errorf("secure ACS Session filesystem: %w", err))
		}
	}
	if materializer != nil {
		if err := materializer.Materialize(created.homeDirectory); err != nil {
			return cleanupFailure(fmt.Errorf("materialize ACS Session: %w", err))
		}
	}
	return created, nil
}

func (session *Session) RootDirectory() string      { return session.lease.RootDir }
func (session *Session) HomeDirectory() string      { return session.homeDirectory }
func (session *Session) TemporaryDirectory() string { return session.temporaryDirectory }
func (session *Session) SessionsDirectory() string  { return session.sessionsDirectory }
func (session *Session) WorkingDirectory() string   { return session.workingDirectory }

// VerificationContext describes this Session to optional target-specific
// verification code.
func (session *Session) VerificationContext() launch.VerificationContext {
	return launch.VerificationContext{
		SessionsDirectory:  session.sessionsDirectory,
		SessionDirectory:   session.RootDirectory(),
		SessionHome:        session.homeDirectory,
		TemporaryDirectory: session.temporaryDirectory,
		WorkingDirectory:   session.workingDirectory,
	}
}

// RetainUntilProcessDone prevents Session deletion until the contained process
// tree has been proven dead by its native sandbox backend.
func (session *Session) RetainUntilProcessDone(process launch.Process) (launch.Process, error) {
	return launch.RetainSessionUntilProcessDone(process, session.lease)
}

// Remove releases ownership of the leased Session and deletes it once every
// retained contained process has completed cleanup.
func (session *Session) Remove() error {
	return session.lease.Remove()
}

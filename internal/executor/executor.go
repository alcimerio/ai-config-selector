// Package executor owns the contained-process lifecycle for ACS's fixed shell.
package executor

import (
	"context"
	"errors"
	"os/exec"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

const systemShell = "/bin/zsh"

// ShellRequest contains the target-independent inputs needed to create a
// credential-free Session and attach ACS's fixed interactive shell.
type ShellRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	Materializer      session.Materializer
	Terminal          launch.Terminal
}

// Executor owns the fixed shell's sandbox check, Session lifecycle, and
// process settlement. Its backend is selected by ACS, never by an adapter.
type Executor struct{ sandbox launch.ProcessSandbox }

// New returns the production executor using ACS's required native sandbox.
func New() *Executor { return newExecutor(launch.NewProcessSandbox()) }

// newExecutor exists only for executor package tests. Production callers must
// use New so they cannot choose a sandbox backend.
func newExecutor(sandbox launch.ProcessSandbox) *Executor { return &Executor{sandbox: sandbox} }

// Readiness reports the fixed shell backend's passive readiness. It neither
// creates a Session nor prepares a process.
func (e *Executor) Readiness(ctx context.Context) (launch.SandboxReadiness, error) {
	if e == nil || e.sandbox == nil {
		return launch.SandboxReadiness{}, errors.New("contained shell executor is unavailable")
	}
	return e.sandbox.Readiness(ctx)
}

// RunShell creates and materializes a Session, then runs exactly /bin/zsh -f.
// A Session is retained until backend cleanup proves the whole process tree is
// gone; cleanup uncertainty and finalization failures outrank an ordinary exit.
func (e *Executor) RunShell(ctx context.Context, request ShellRequest) (resultErr error) {
	if e == nil || e.sandbox == nil {
		return errors.New("contained shell executor is unavailable")
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: request.WorkingDirectory, SessionsDirectory: request.SessionsDirectory,
		Executable: systemShell,
	}); err != nil {
		return err
	}
	created, err := session.Create(request.SessionsDirectory, request.WorkingDirectory, request.Materializer)
	if err != nil {
		return err
	}
	defer func() {
		if err := created.Remove(); err != nil {
			resultErr = cleanupPrecedence(resultErr, err)
		}
	}()
	process, err := e.sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: systemShell,
		Arguments: []string{"-f"}, Terminal: request.Terminal,
	})
	if err != nil {
		return err
	}
	process, err = created.RetainUntilProcessDone(process)
	if err != nil {
		return err
	}
	runErr := launch.RunAttached(process)
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
		return cleanupPrecedence(runErr, cleanupErr)
	}
	return runErr
}

func cleanupPrecedence(outcome, cleanup error) error {
	if outcome == nil {
		return cleanup
	}
	var targetExit *exec.ExitError
	var exitCoder interface{ ExitCode() int }
	if errors.As(outcome, &targetExit) || errors.As(outcome, &exitCoder) {
		return cleanup
	}
	return errors.Join(outcome, cleanup)
}

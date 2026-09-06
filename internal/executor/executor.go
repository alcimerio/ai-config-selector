// Package executor owns the contained-process lifecycle for ACS's registered
// targets. Target adapters supply validated declarative inputs; this package
// owns checks, Sessions, contained processes, and cleanup.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/skills"
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

// DevinRequest is the fixed registered Devin lifecycle input. Its command
// shapes, credential destination, probe ordering, and sandbox choice are not
// adapter-controlled.
type DevinRequest struct {
	SessionsDirectory     string
	WorkingDirectory      string
	Materializer          session.Materializer
	Terminal              launch.Terminal
	Executable            string
	RuntimeInputs         []string
	ExistingHomeDirectory string
	ExpectedCatalog       []skills.SkillReference
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
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
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

// RunDevin performs the complete fixed Devin lifecycle. It captures signals
// before Check so a termination during either preflight cannot become an
// interactive launch, and it never permits a caller-owned Session lease.
func (e *Executor) RunDevin(ctx context.Context, request DevinRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained Devin executor is unavailable")
	}
	preflightContext, cancelPreflight := context.WithCancel(ctx)
	defer cancelPreflight()
	supervisor := newDevinSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	if err := e.sandbox.Check(preflightContext, launch.SandboxCheck{Workspace: request.WorkingDirectory, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs}); err != nil {
		return 1, err
	}
	created, err := session.Create(request.SessionsDirectory, request.WorkingDirectory, request.Materializer)
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := created.Remove(); err != nil {
			resultErr = cleanupPrecedence(resultErr, err)
			exitCode = 1
		}
	}()
	if err := copyDevinCredentialIfPresent(filepath.Join(request.ExistingHomeDirectory, ".local", "share", "devin", "credentials.toml"), filepath.Join(created.HomeDirectory(), ".local", "share", "devin", "credentials.toml")); err != nil {
		return 1, err
	}
	if err := e.verifyDevinSkills(preflightContext, created, request); err != nil {
		return 1, err
	}
	if err := e.verifyDevinAuthentication(preflightContext, created, request); err != nil {
		return 1, err
	}
	if preflightContext.Err() != nil {
		return 1, errors.New("Devin launch interrupted before the interactive process started")
	}
	process, err := e.prepareDevin(preflightContext, created, request, []string{"--respect-workspace-trust", "false"}, request.Terminal)
	if err != nil {
		return 1, err
	}
	runErr := runDevinAttached(process, supervisor)
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
		return 1, cleanupPrecedence(runErr, cleanupErr)
	}
	if runErr == nil {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 1, fmt.Errorf("Devin launch interrupted: %w", ctx.Err())
	}
	if preflightContext.Err() != nil {
		return 1, errors.New("Devin launch interrupted before the interactive process started")
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), exitCodeError(128 + int(status.Signal()))
		}
		if code := exitError.ExitCode(); code >= 0 {
			return code, exitCodeError(code)
		}
	}
	return 1, fmt.Errorf("start Devin: %w", runErr)
}

// VerifyDevin performs the registered Devin checks in a protected temporary
// Session without attaching the interactive target. It is the opt-in smoke
// entrypoint: callers provide declarative data, never a Session or process.
func (e *Executor) VerifyDevin(ctx context.Context, request DevinRequest) (resultErr error) {
	if e == nil || e.sandbox == nil {
		return errors.New("contained Devin executor is unavailable")
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: request.WorkingDirectory, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs}); err != nil {
		return err
	}
	created, err := session.Create(request.SessionsDirectory, request.WorkingDirectory, request.Materializer)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
		}
	}()
	if err := copyDevinCredentialIfPresent(filepath.Join(request.ExistingHomeDirectory, ".local", "share", "devin", "credentials.toml"), filepath.Join(created.HomeDirectory(), ".local", "share", "devin", "credentials.toml")); err != nil {
		return err
	}
	if err := e.verifyDevinSkills(ctx, created, request); err != nil {
		return err
	}
	return e.verifyDevinAuthentication(ctx, created, request)
}

// DevinExit is intentionally small: the adapter translates it to its stable
// public compatibility error without exposing process details.
type DevinExit interface {
	error
	ExitCode() int
}
type exitCodeError int

func (e exitCodeError) Error() string { return "Devin exited" }
func (e exitCodeError) ExitCode() int { return int(e) }

func (e *Executor) verifyDevinSkills(ctx context.Context, created *session.Session, request DevinRequest) error {
	output, err := e.runDevinProbe(ctx, created, request, []string{"skills", "list", "--json"})
	if err != nil {
		return devinPreflightFailure(ctx, err, devinruntime.CapabilitySkillIsolation, devinruntime.ReasonSkillInspectionCommandFailed)
	}
	observed, failure := devinruntime.InterpretCatalog(created.HomeDirectory(), created.WorkingDirectory(), output)
	if failure != 0 {
		return devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, failure)
	}
	expected := append([]skills.SkillReference(nil), request.ExpectedCatalog...)
	devinruntime.SortSkillReferences(expected)
	if observed.HasUnmanagedSource() || !devinruntime.EqualSkillReferences(expected, observed.ManagedReferences()) {
		return devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, devinruntime.ReasonCatalogMismatch)
	}
	return nil
}

func (e *Executor) verifyDevinAuthentication(ctx context.Context, created *session.Session, request DevinRequest) error {
	output, err := e.runDevinProbe(ctx, created, request, []string{"auth", "status"})
	if err != nil {
		return devinPreflightFailure(ctx, err, devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationCommandFailed)
	}
	if !devinruntime.AuthenticationLoggedIn(output) {
		return devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationUnavailable)
	}
	return nil
}

func devinPreflightFailure(ctx context.Context, err error, capability devinruntime.Capability, fallback devinruntime.PreflightFailureReason) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return err
	}
	if ctx.Err() != nil {
		return devinruntime.NewPreflightError(capability, devinruntime.ReasonVerificationInterrupted)
	}
	var executableError *exec.Error
	if errors.As(err, &executableError) || errors.Is(err, os.ErrNotExist) {
		return devinruntime.NewPreflightError(capability, devinruntime.ReasonExecutableUnavailable)
	}
	return devinruntime.NewPreflightError(capability, fallback)
}

func (e *Executor) runDevinProbe(ctx context.Context, created *session.Session, request DevinRequest, arguments []string) ([]byte, error) {
	var output bytes.Buffer
	process, err := e.prepareDevin(ctx, created, request, arguments, launch.Terminal{Output: &output, ErrorOutput: io.Discard})
	if err != nil {
		return nil, err
	}
	runErr := process.Start()
	if runErr == nil {
		runErr = process.Wait()
	}
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
		// A probe cannot safely advance while its retained tree is uncertain;
		// cleanup proof therefore outranks every probe outcome.
		return nil, cleanupErr
	}
	return output.Bytes(), runErr
}

func (e *Executor) prepareDevin(ctx context.Context, created *session.Session, request DevinRequest, arguments []string, terminal launch.Terminal) (launch.Process, error) {
	process, err := e.sandbox.Prepare(ctx, launch.ProcessRequest{Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, Arguments: arguments, Terminal: terminal})
	if err != nil {
		return nil, err
	}
	return created.RetainUntilProcessDone(process)
}

func copyDevinCredentialIfPresent(source, destination string) error {
	info, err := os.Stat(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("allowlisted credentials could not be inspected safely")
	}
	if !info.Mode().IsRegular() {
		return errors.New("allowlisted credentials path is not a regular file")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return errors.New("allowlisted credentials could not be copied safely")
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("allowlisted credentials could not be copied safely")
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		return errors.New("allowlisted credentials could not be copied safely")
	}
	return os.Chmod(destination, 0o600)
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

type devinSignalSupervisor struct {
	forwarded       chan os.Signal
	done            chan struct{}
	cancelPreflight context.CancelFunc
	mutex           sync.Mutex
	child           launch.Process
	pending         os.Signal
	starting        bool
}

func newDevinSignalSupervisor(cancel context.CancelFunc) *devinSignalSupervisor {
	s := &devinSignalSupervisor{forwarded: make(chan os.Signal, 1), done: make(chan struct{}), cancelPreflight: cancel}
	signal.Notify(s.forwarded, os.Interrupt, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGWINCH)
	go s.run()
	return s
}
func (s *devinSignalSupervisor) run() {
	for {
		select {
		case received := <-s.forwarded:
			s.mutex.Lock()
			child := s.child
			if child == nil {
				if s.starting {
					s.pending = received
					s.mutex.Unlock()
					continue
				}
				if received != syscall.SIGWINCH {
					s.pending = received
					s.cancelPreflight()
				}
				s.mutex.Unlock()
				continue
			}
			s.mutex.Unlock()
			_ = child.Signal(received)
		case <-s.done:
			return
		}
	}
}
func (s *devinSignalSupervisor) start(child launch.Process) (bool, error) {
	s.mutex.Lock()
	if s.pending != nil {
		s.mutex.Unlock()
		return false, errors.New("Devin launch interrupted before the interactive process started")
	}
	s.starting = true
	s.mutex.Unlock()
	err := child.Start()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.starting = false
	if err != nil {
		return false, err
	}
	s.child = child
	pending := s.pending
	s.pending = nil
	if pending == nil {
		return true, nil
	}
	s.mutex.Unlock()
	err = child.Signal(pending)
	s.mutex.Lock()
	if err != nil {
		return true, &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	return true, nil
}
func (s *devinSignalSupervisor) detach() { s.mutex.Lock(); defer s.mutex.Unlock(); s.child = nil }
func (s *devinSignalSupervisor) stop()   { signal.Stop(s.forwarded); close(s.done) }
func runDevinAttached(process launch.Process, supervisor *devinSignalSupervisor) error {
	started, startErr := supervisor.start(process)
	if !started {
		return startErr
	}
	defer supervisor.detach()
	waitErr := process.Wait()
	if startErr == nil {
		return waitErr
	}
	if waitErr == nil {
		return startErr
	}
	return errors.Join(startErr, &launch.SandboxError{Category: launch.SandboxProcessWaitFailed})
}

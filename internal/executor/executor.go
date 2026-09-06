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
	"reflect"
	"sync"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const systemShell = "/bin/zsh"

// ShellRequest contains the target-independent inputs needed to create a
// credential-free Session and attach ACS's fixed interactive shell.
type ShellRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	WorkspaceAccess   launch.WorkspaceAccess
	Materializer      session.Materializer
	ResolvedPlan      *authority.Plan
	Terminal          launch.Terminal
}

// DevinRequest is the fixed registered Devin lifecycle input. Its command
// shapes, credential destination, probe ordering, and sandbox choice are not
// adapter-controlled.
type DevinRequest struct {
	SessionsDirectory     string
	WorkingDirectory      string
	WorkspaceAccess       launch.WorkspaceAccess
	Materializer          session.Materializer
	Terminal              launch.Terminal
	Executable            string
	RuntimeInputs         []string
	ExistingHomeDirectory string
	ExpectedCatalog       []skills.SkillReference
	ResolvedPlan          *authority.Plan
}

// CommandRequest contains one already-resolved literal command and the common
// Profile authority under which the shared executor must run it.
type CommandRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	ResolvedPlan      *authority.Plan
	Command           runcommand.Command
	Terminal          launch.Terminal
}

func (request ShellRequest) resolvedInputs() (launch.WorkspaceAccess, session.Materializer) {
	if request.ResolvedPlan != nil {
		return request.ResolvedPlan.WorkspaceAccess(), *request.ResolvedPlan
	}
	return request.WorkspaceAccess, request.Materializer
}
func (request DevinRequest) resolvedInputs() (launch.WorkspaceAccess, session.Materializer, []skills.SkillReference, authority.TargetRequirements) {
	if request.ResolvedPlan != nil {
		return request.ResolvedPlan.WorkspaceAccess(), *request.ResolvedPlan, request.ResolvedPlan.DevinExpectedCatalog(), request.ResolvedPlan.Requirements()
	}
	return request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog, authority.TargetRequirements{
		Recipe: authority.RecipeDevin, Executable: request.Executable,
		RuntimeInputs: request.RuntimeInputs, ExistingHomeDirectory: request.ExistingHomeDirectory,
	}
}

// Executor owns the fixed shell's sandbox check, Session lifecycle, and
// process settlement. Its backend is selected by ACS, never by an adapter.
type Executor struct{ sandbox launch.ProcessSandbox }

type retainedSignalMode uint8

const (
	retainedProbe retainedSignalMode = iota
	retainedAttached
	retainedDevinReserved
)

var errRetainPreparedProcess = errors.New("retain prepared process")
var errInvalidPreparedProcess = &launch.SandboxError{Category: launch.SandboxSetupFailed}

func isNilProcess(process launch.Process) bool {
	if process == nil {
		return true
	}
	value := reflect.ValueOf(process)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (e *Executor) prepareRetainedProcess(ctx context.Context, created *session.Session, request launch.ProcessRequest) (launch.Process, error) {
	process, err := e.sandbox.Prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	if isNilProcess(process) {
		return nil, errInvalidPreparedProcess
	}
	retained, err := created.RetainUntilProcessDone(process)
	if err != nil {
		return nil, errors.Join(errRetainPreparedProcess, err)
	}
	return retained, nil
}

func settleRetainedProcess(process launch.Process, mode retainedSignalMode, devinSupervisor *devinSignalSupervisor) (error, error) {
	var runErr error
	switch mode {
	case retainedProbe:
		runErr = process.Start()
		if runErr == nil {
			runErr = process.Wait()
		}
	case retainedAttached:
		runErr = launch.RunAttached(process)
	case retainedDevinReserved:
		if devinSupervisor == nil {
			runErr = errors.New("contained Devin signal supervisor is unavailable")
		} else {
			runErr = runDevinAttachedReserved(process, devinSupervisor)
		}
	default:
		runErr = errors.New("contained process signal mode is invalid")
	}
	return runErr, launch.AwaitRetainedSessionCleanup(process)
}

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
	workspaceAccess, materializer := request.resolvedInputs()
	if request.ResolvedPlan != nil && request.ResolvedPlan.Requirements().Recipe != authority.RecipeShell {
		return errors.New("resolved authority does not select the shell execution recipe")
	}
	resultErr, _ = e.runAttached(ctx, attachedRecipe{
		sessionsDirectory: request.SessionsDirectory, workingDirectory: request.WorkingDirectory,
		workspaceAccess: workspaceAccess, materializer: materializer,
		executable: systemShell, arguments: []string{"-f"}, terminal: request.Terminal,
	})
	return resultErr
}

type attachedRecipe struct {
	sessionsDirectory string
	workingDirectory  string
	workspaceAccess   launch.WorkspaceAccess
	materializer      session.Materializer
	executable        string
	arguments         []string
	command           *runcommand.Command
	terminal          launch.Terminal
}

// runAttached is the one Session/process lifecycle for the fixed shell and an
// explicit generic command. Command identity validation is declarative and
// remains inside this shared lifecycle; there are no adapter callbacks.
func (e *Executor) runAttached(ctx context.Context, recipe attachedRecipe) (resultErr error, cleanupFailed bool) {
	executable, arguments := recipe.executable, append([]string(nil), recipe.arguments...)
	if recipe.command != nil {
		var err error
		executable, arguments, err = recipe.command.Revalidate(recipe.workingDirectory)
		if err != nil {
			return err, false
		}
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: recipe.workingDirectory,
		WorkspaceAccess: recipe.workspaceAccess, SessionsDirectory: recipe.sessionsDirectory,
		Executable: executable}); err != nil {
		return err, false
	}
	created, err := session.Create(recipe.sessionsDirectory, recipe.workingDirectory, recipe.materializer)
	if err != nil {
		return err, false
	}
	defer func() {
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
			cleanupFailed = true
		}
	}()
	if recipe.command != nil {
		executable, arguments, err = recipe.command.Revalidate(created.WorkingDirectory())
		if err != nil {
			return err, false
		}
	}
	process, err := e.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), WorkspaceAccess: recipe.workspaceAccess,
		SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(),
		SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(),
		Executable: executable, Arguments: arguments, Terminal: recipe.terminal,
	})
	if err != nil {
		return err, false
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedAttached, nil)
	if cleanupErr != nil {
		return cleanupPrecedence(runErr, cleanupErr), true
	}
	return runErr, false
}

// RunCommand executes one literal argv through the same mandatory Session,
// sandbox, attachment, settlement, and cleanup lifecycle as fixed targets.
func (e *Executor) RunCommand(ctx context.Context, request CommandRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained command executor is unavailable")
	}
	if request.ResolvedPlan == nil || request.ResolvedPlan.Requirements().Recipe != authority.RecipeCommand {
		return 1, errors.New("resolved authority does not select the command execution recipe")
	}
	runErr, cleanupFailed := e.runAttached(ctx, attachedRecipe{
		sessionsDirectory: request.SessionsDirectory, workingDirectory: request.WorkingDirectory,
		workspaceAccess: request.ResolvedPlan.WorkspaceAccess(), materializer: *request.ResolvedPlan,
		command: &request.Command, terminal: request.Terminal,
	})
	if cleanupFailed {
		return 1, runErr
	}
	if ctx.Err() != nil {
		return 130, context.Canceled
	}
	if runErr == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code := 128 + int(status.Signal())
			return code, exitCodeError(code)
		}
		if code := exitError.ExitCode(); code >= 0 {
			return code, exitCodeError(code)
		}
	}
	return 1, runErr
}

// RunDevin performs the complete fixed Devin lifecycle. It captures signals
// before Check so a termination during either preflight cannot become an
// interactive launch, and it never permits a caller-owned Session lease.
func (e *Executor) RunDevin(ctx context.Context, request DevinRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained Devin executor is unavailable")
	}
	workspaceAccess, materializer, expectedCatalog, requirements := request.resolvedInputs()
	if requirements.Recipe != authority.RecipeDevin {
		return 1, errors.New("resolved authority does not select the Devin execution recipe")
	}
	request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog = workspaceAccess, materializer, expectedCatalog
	request.Executable, request.RuntimeInputs, request.ExistingHomeDirectory = requirements.Executable, requirements.RuntimeInputs, requirements.ExistingHomeDirectory
	preflightContext, cancelPreflight := context.WithCancel(ctx)
	defer cancelPreflight()
	supervisor := newDevinSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	if err := e.sandbox.Check(preflightContext, launch.SandboxCheck{Workspace: request.WorkingDirectory, WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs}); err != nil {
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
	process, err := e.prepareDevinInteractive(preflightContext, created, request, supervisor)
	if err != nil {
		return 1, err
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedDevinReserved, supervisor)
	if cleanupErr != nil {
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
	workspaceAccess, materializer, expectedCatalog, requirements := request.resolvedInputs()
	if requirements.Recipe != authority.RecipeDevin {
		return errors.New("resolved authority does not select the Devin execution recipe")
	}
	request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog = workspaceAccess, materializer, expectedCatalog
	request.Executable, request.RuntimeInputs, request.ExistingHomeDirectory = requirements.Executable, requirements.RuntimeInputs, requirements.ExistingHomeDirectory
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: request.WorkingDirectory, WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs}); err != nil {
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
	runErr, cleanupErr := settleRetainedProcess(process, retainedProbe, nil)
	if cleanupErr != nil {
		// A probe cannot safely advance while its retained tree is uncertain;
		// cleanup proof therefore outranks every probe outcome.
		return nil, cleanupErr
	}
	return output.Bytes(), runErr
}

func (e *Executor) prepareDevin(ctx context.Context, created *session.Session, request DevinRequest, arguments []string, terminal launch.Terminal) (launch.Process, error) {
	return e.prepareRetainedProcess(ctx, created, launch.ProcessRequest{Workspace: created.WorkingDirectory(), WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, Arguments: arguments, Terminal: terminal})
}

// prepareDevinInteractive commits the handoff before a process reference can
// retain its Session. Signals after that commitment are queued for replay once
// the prepared target has started; a failed preparation ends the commitment
// without starting a target.
func (e *Executor) prepareDevinInteractive(ctx context.Context, created *session.Session, request DevinRequest, supervisor *devinSignalSupervisor) (launch.Process, error) {
	if err := supervisor.reserveInteractive(); err != nil {
		return nil, err
	}
	process, err := e.prepareDevin(ctx, created, request, []string{"--respect-workspace-trust", "false"}, request.Terminal)
	if err != nil {
		supervisor.cancelInteractiveReservation()
		return nil, err
	}
	return process, nil
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
			s.handleSignal(received)
		case <-s.done:
			return
		}
	}
}

func (s *devinSignalSupervisor) handleSignal(received os.Signal) {
	s.mutex.Lock()
	child := s.child
	if child == nil {
		if s.starting {
			// Resize notifications may coalesce, but must never erase a
			// termination already accepted during interactive preparation.
			if s.pending == nil || received != syscall.SIGWINCH {
				s.pending = received
			}
			s.mutex.Unlock()
			return
		}
		if received != syscall.SIGWINCH {
			s.pending = received
			s.cancelPreflight()
		}
		s.mutex.Unlock()
		return
	}
	s.mutex.Unlock()
	_ = child.Signal(received)
}
func (s *devinSignalSupervisor) start(child launch.Process) (bool, error) {
	if err := s.reserveInteractive(); err != nil {
		return false, err
	}
	return s.startReserved(child)
}

// reserveInteractive makes a completed preflight's interactive start
// inevitable if preparation succeeds. It is deliberately private: only the
// executor may make this lifecycle commitment.
func (s *devinSignalSupervisor) reserveInteractive() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.pending != nil {
		return errors.New("Devin launch interrupted before the interactive process started")
	}
	s.starting = true
	return nil
}

func (s *devinSignalSupervisor) cancelInteractiveReservation() {
	s.mutex.Lock()
	s.starting = false
	s.mutex.Unlock()
}

func (s *devinSignalSupervisor) startReserved(child launch.Process) (bool, error) {
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
	return runDevinStarted(process, supervisor, started, startErr)
}
func runDevinAttachedReserved(process launch.Process, supervisor *devinSignalSupervisor) error {
	started, startErr := supervisor.startReserved(process)
	return runDevinStarted(process, supervisor, started, startErr)
}
func runDevinStarted(process launch.Process, supervisor *devinSignalSupervisor, started bool, startErr error) error {
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

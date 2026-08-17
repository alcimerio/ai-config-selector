package devin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// Launch creates an ephemeral ACS Session, verifies the Devin Adapter
// contract, and attaches Devin to the invoking terminal without adding Devin
// command-line options.
func (a *Adapter) Launch(
	ctx context.Context,
	sessionsDirectory string,
	workingDirectory string,
	resolved category.ResolvedProfile,
	terminal launch.Terminal,
) (exitCode int, resultErr error) {
	preflightContext, cancelPreflight := context.WithCancel(ctx)
	defer cancelPreflight()
	supervisor := newSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	if err := a.sandbox.Check(preflightContext, launch.SandboxCheck{
		Workspace: workingDirectory, SessionsDirectory: sessionsDirectory,
		Executable: a.binaryPath, RuntimeInputs: a.runtimeInputs,
	}); err != nil {
		return 1, err
	}

	sessionLease, err := launch.CreateSession(sessionsDirectory)
	if err != nil {
		return 1, sanitizeLaunchError(err)
	}
	sessionRoot := sessionLease.RootDir
	defer func() {
		if err := sessionLease.Remove(); err != nil {
			cleanupFailure := sanitizeLaunchError(err)
			var targetExit *DevinExitError
			if errors.As(resultErr, &targetExit) {
				// A cleanup failure means ACS may have left sensitive Session
				// state behind. Do not join it with DevinExitError: callers use
				// that interface to preserve ordinary target exit codes.
				resultErr = cleanupFailure
			} else if resultErr != nil {
				resultErr = errors.Join(resultErr, cleanupFailure)
			} else {
				resultErr = cleanupFailure
			}
			exitCode = 1
		}
	}()
	session, err := a.prepareResolvedSession(sessionRoot, workingDirectory, resolved)
	if err != nil {
		return 1, sanitizeLaunchError(err)
	}
	session.lease = sessionLease
	if err := resolved.Verify(preflightContext, launch.VerificationContext{
		SessionsDirectory:  sessionsDirectory,
		SessionDirectory:   session.RootDir,
		SessionHome:        session.HomeDir,
		TemporaryDirectory: session.TemporaryDir,
		WorkingDirectory:   session.WorkingDirectory,
	}); err != nil {
		return 1, sanitizeLaunchError(err)
	}
	if err := a.verifyAuthentication(preflightContext, session); err != nil {
		return 1, sanitizeLaunchError(err)
	}
	if preflightContext.Err() != nil {
		return 1, errors.New("Devin launch interrupted before the interactive process started")
	}

	process, err := a.sandbox.Prepare(preflightContext, launch.ProcessRequest{
		Workspace: session.WorkingDirectory, SessionsDirectory: sessionsDirectory,
		SessionDirectory: session.RootDir, SessionHome: session.HomeDir,
		TemporaryDirectory: session.TemporaryDir, Executable: a.binaryPath,
		RuntimeInputs: a.runtimeInputs, Terminal: terminal,
	})
	if err != nil {
		return 1, sanitizeLaunchError(err)
	}
	process, err = launch.RetainSessionUntilProcessDone(process, sessionLease)
	if err != nil {
		return 1, err
	}
	if err := runAttached(process, supervisor); err != nil {
		if ctx.Err() != nil {
			return 1, fmt.Errorf("Devin launch interrupted: %w", ctx.Err())
		}
		if preflightContext.Err() != nil {
			return 1, errors.New("Devin launch interrupted before the interactive process started")
		}
		var sandboxFailure *launch.SandboxError
		if errors.As(err, &sandboxFailure) {
			return 1, sanitizeLaunchError(err)
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
				return 1, sanitizeLaunchError(cleanupErr)
			}
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return 128 + int(status.Signal()), &DevinExitError{Code: 128 + int(status.Signal())}
			}
			if exitCode := exitError.ExitCode(); exitCode >= 0 {
				return exitCode, &DevinExitError{Code: exitCode}
			}
		}
		return 1, fmt.Errorf("start Devin: %w", err)
	}
	return 0, nil
}

// sanitizeLaunchError preserves the fixed sandbox and preflight diagnostics
// while converting every other launch-preparation error into one safe category.
// In particular, filesystem failures must not expose Session, credential, or
// workspace paths through the CLI.
func sanitizeLaunchError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	var preflightFailure *PreflightError
	if errors.As(err, &preflightFailure) {
		return preflightFailure
	}
	return &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

func runAttached(process launch.Process, supervisor *signalSupervisor) error {
	started, startErr := supervisor.start(process)
	if !started {
		return startErr
	}
	defer supervisor.detach()
	waitErr := process.Wait()
	if startErr == nil {
		return waitErr
	}
	// A replay failure is reported as the primary launch failure, but a
	// successful Start has made the process and its Session lease live. Always
	// reap it before returning; expose only stable sandbox categories on this
	// otherwise sensitive error path.
	if waitErr == nil {
		return startErr
	}
	return errors.Join(startErr, &launch.SandboxError{Category: launch.SandboxProcessWaitFailed})
}

type signalSupervisor struct {
	forwarded       chan os.Signal
	done            chan struct{}
	cancelPreflight context.CancelFunc
	mutex           sync.Mutex
	child           launch.Process
	pending         os.Signal
	starting        bool
}

func newSignalSupervisor(cancelPreflight context.CancelFunc) *signalSupervisor {
	supervisor := &signalSupervisor{
		forwarded:       make(chan os.Signal, 1),
		done:            make(chan struct{}),
		cancelPreflight: cancelPreflight,
	}
	signal.Notify(
		supervisor.forwarded,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGWINCH,
	)
	go supervisor.run()
	return supervisor
}

func (supervisor *signalSupervisor) run() {
	for {
		select {
		case received := <-supervisor.forwarded:
			supervisor.mutex.Lock()
			child := supervisor.child
			if child == nil {
				if supervisor.starting {
					supervisor.pending = received
					supervisor.mutex.Unlock()
					continue
				}
				if received != syscall.SIGWINCH {
					supervisor.pending = received
					supervisor.cancelPreflight()
				}
				supervisor.mutex.Unlock()
				continue
			}
			supervisor.mutex.Unlock()
			// Native launchers place the contained controller in the terminal's
			// foreground process group. A signal observed by ACS is therefore
			// addressed to ACS, rather than a duplicate terminal-generated signal.
			_ = child.Signal(received)
		case <-supervisor.done:
			return
		}
	}
}

func (supervisor *signalSupervisor) start(child launch.Process) (bool, error) {
	supervisor.mutex.Lock()
	if supervisor.pending != nil {
		supervisor.mutex.Unlock()
		return false, errors.New("Devin launch interrupted before the interactive process started")
	}
	supervisor.starting = true
	supervisor.mutex.Unlock()

	err := child.Start()
	supervisor.mutex.Lock()
	defer supervisor.mutex.Unlock()
	supervisor.starting = false
	if err != nil {
		return false, err
	}
	supervisor.child = child
	pending := supervisor.pending
	supervisor.pending = nil
	if pending == nil {
		return true, nil
	}
	supervisor.mutex.Unlock()
	err = child.Signal(pending)
	supervisor.mutex.Lock()
	if err != nil {
		return true, &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	return true, nil
}

func (supervisor *signalSupervisor) detach() {
	supervisor.mutex.Lock()
	defer supervisor.mutex.Unlock()
	supervisor.child = nil
}

func (supervisor *signalSupervisor) stop() {
	signal.Stop(supervisor.forwarded)
	close(supervisor.done)
}

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
		return 1, err
	}
	sessionRoot := sessionLease.RootDir
	defer func() {
		if err := sessionLease.Remove(); err != nil {
			cleanupFailure := err
			if resultErr != nil {
				resultErr = errors.Join(resultErr, cleanupFailure)
			} else {
				resultErr = cleanupFailure
			}
			exitCode = 1
		}
	}()
	session, err := a.prepareResolvedSession(sessionRoot, workingDirectory, resolved)
	if err != nil {
		return 1, err
	}
	session.lease = sessionLease
	if err := resolved.Verify(preflightContext, launch.VerificationContext{
		SessionsDirectory:  sessionsDirectory,
		SessionDirectory:   session.RootDir,
		SessionHome:        session.HomeDir,
		TemporaryDirectory: session.TemporaryDir,
		WorkingDirectory:   session.WorkingDirectory,
	}); err != nil {
		return 1, err
	}
	if err := a.verifyAuthentication(preflightContext, session); err != nil {
		return 1, err
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
		return 1, err
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
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
			if exitCode := exitError.ExitCode(); exitCode >= 0 {
				return exitCode, nil
			}
		}
		return 1, fmt.Errorf("start Devin: %w", err)
	}
	return 0, nil
}

func runAttached(process launch.Process, supervisor *signalSupervisor) error {
	if err := supervisor.start(process); err != nil {
		return err
	}
	err := process.Wait()
	supervisor.detach()
	return err
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

func (supervisor *signalSupervisor) start(child launch.Process) error {
	supervisor.mutex.Lock()
	if supervisor.pending != nil {
		supervisor.mutex.Unlock()
		return errors.New("Devin launch interrupted before the interactive process started")
	}
	supervisor.starting = true
	supervisor.mutex.Unlock()

	err := child.Start()
	supervisor.mutex.Lock()
	defer supervisor.mutex.Unlock()
	supervisor.starting = false
	if err != nil {
		return err
	}
	supervisor.child = child
	pending := supervisor.pending
	supervisor.pending = nil
	if pending == nil {
		return nil
	}
	supervisor.mutex.Unlock()
	err = child.Signal(pending)
	supervisor.mutex.Lock()
	return err
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

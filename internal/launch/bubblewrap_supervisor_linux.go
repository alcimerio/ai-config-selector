//go:build linux

package launch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

const bubblewrapTargetSupervisorFlag = "--acs-bubblewrap-target-supervisor"

type bubblewrapSupervisorExitError struct {
	code int
}

func (err *bubblewrapSupervisorExitError) Error() string {
	return fmt.Sprintf("Bubblewrap target exited with status %d", err.code)
}

// BubblewrapHelperExitCode identifies an intentional target exit propagated by
// the in-sandbox supervisor. Callers should exit with this code without
// turning the target's ordinary status into a helper failure.
func BubblewrapHelperExitCode(err error) (int, bool) {
	var targetExit *bubblewrapSupervisorExitError
	if errors.As(err, &targetExit) {
		return targetExit.code, true
	}
	return 0, false
}

func runBubblewrapTargetSupervisor(arguments []string) error {
	if len(arguments) == 0 || arguments[0] == "" {
		return errors.New("missing Bubblewrap target")
	}
	command := exec.Command(arguments[0], arguments[1:]...)
	command.Env = os.Environ()
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	terminal, foregroundGroup := bubblewrapSupervisorTerminal()
	if terminal >= 0 {
		command.SysProcAttr.Foreground = true
		command.SysProcAttr.Ctty = terminal
	}
	signals := make(chan os.Signal, len(bubblewrapSupervisorSignals))
	signal.Notify(signals, bubblewrapSupervisorSignals...)
	defer signal.Stop(signals)
	if err := command.Start(); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	for {
		select {
		case received := <-signals:
			if err := command.Process.Signal(received); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
		case err := <-wait:
			if terminal >= 0 {
				_ = setBubblewrapForegroundProcessGroup(os.Stdin, foregroundGroup)
			}
			return bubblewrapTargetExit(err)
		}
	}
}

var bubblewrapSupervisorSignals = []os.Signal{
	syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL,
	syscall.SIGTRAP, syscall.SIGABRT, syscall.SIGBUS, syscall.SIGFPE,
	syscall.SIGUSR1, syscall.SIGSEGV, syscall.SIGUSR2, syscall.SIGPIPE,
	syscall.SIGALRM, syscall.SIGTERM, syscall.SIGSTKFLT, syscall.SIGXCPU,
	syscall.SIGXFSZ, syscall.SIGVTALRM, syscall.SIGPROF, syscall.SIGWINCH,
	syscall.SIGIO, syscall.SIGPWR, syscall.SIGSYS,
}

func bubblewrapSupervisorTerminal() (int, int) {
	terminal := int(os.Stdin.Fd())
	foregroundGroup, err := unix.IoctlGetInt(terminal, unix.TIOCGPGRP)
	if err != nil {
		return -1, 0
	}
	return terminal, foregroundGroup
}

func bubblewrapTargetExit(err error) error {
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return err
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		return err
	}
	if status.Exited() {
		return &bubblewrapSupervisorExitError{code: status.ExitStatus()}
	}
	if status.Signaled() {
		return &bubblewrapSupervisorExitError{code: 128 + int(status.Signal())}
	}
	return err
}

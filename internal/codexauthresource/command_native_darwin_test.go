//go:build darwin

package codexauthresource_test

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func nativeCommand(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	return nativeCommandWithTimeout(t, 30*time.Second, name, args...)
}

func nativeCommandWithTimeout(t *testing.T, timeout time.Duration, name string, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		// PTY callers replace Setpgid with Setsid, which also creates a process
		// group. Settle children holding output pipes as well as ACS itself.
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
			if err == syscall.ESRCH {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	return command
}

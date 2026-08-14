//go:build linux

package launch

import (
	"context"
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const bubblewrapHelperFlag = "--acs-bubblewrap-helper"

func RunBubblewrapHelper(arguments []string) (bool, error) {
	if len(arguments) == 0 || arguments[0] != bubblewrapHelperFlag {
		return false, nil
	}
	if len(arguments) == 1 {
		return true, errors.New("missing Bubblewrap arguments")
	}
	return true, execBubblewrap(arguments[1:])
}

func execBubblewrap(arguments []string) error {
	argv := make([]string, 1, len(arguments)+1)
	argv[0] = bubblewrapExecutable
	argv = append(argv, arguments...)
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	return syscall.Exec(bubblewrapExecutable, argv, []string{})
}

func newBubblewrapCommand(ctx context.Context, arguments []string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, "/proc/self/exe", bubblewrapHelperArguments(arguments)...), nil
}

func bubblewrapHelperArguments(arguments []string) []string {
	return append([]string{bubblewrapHelperFlag}, arguments...)
}

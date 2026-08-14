//go:build linux

package launch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const bubblewrapHelperFlag = "--acs-bubblewrap-helper"

const maximumBubblewrapHelperDescriptors = 2

func RunBubblewrapHelper(arguments []string) (bool, error) {
	if len(arguments) == 0 || arguments[0] != bubblewrapHelperFlag {
		return false, nil
	}
	if len(arguments) < 3 {
		return true, errors.New("missing Bubblewrap arguments")
	}
	descriptors, err := strconv.Atoi(arguments[1])
	if err != nil || (descriptors != 0 && descriptors != maximumBubblewrapHelperDescriptors) {
		return true, errors.New("invalid Bubblewrap helper descriptor count")
	}
	return true, execBubblewrap(arguments[2:], descriptors)
}

func execBubblewrap(arguments []string, descriptors int) error {
	argv := make([]string, 1, len(arguments)+1)
	argv[0] = bubblewrapExecutable
	argv = append(argv, arguments...)
	if err := unix.CloseRange(uint(3+descriptors), ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	return syscall.Exec(bubblewrapExecutable, argv, []string{})
}

func newBubblewrapCommand(ctx context.Context, arguments []string, descriptors ...*os.File) (*exec.Cmd, error) {
	if len(descriptors) != 0 && len(descriptors) != maximumBubblewrapHelperDescriptors {
		return nil, fmt.Errorf("invalid Bubblewrap descriptor count")
	}
	command := exec.CommandContext(ctx, "/proc/self/exe", bubblewrapHelperArguments(arguments, len(descriptors))...)
	command.ExtraFiles = descriptors
	return command, nil
}

func bubblewrapHelperArguments(arguments []string, descriptors int) []string {
	return append([]string{bubblewrapHelperFlag, strconv.Itoa(descriptors)}, arguments...)
}

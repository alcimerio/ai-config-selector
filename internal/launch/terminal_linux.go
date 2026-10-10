package launch

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

var errLinuxSeal = errors.New("Linux launcher sealing failed")

// Only explicitly supplied stdio crosses the boundary. A connected socket,
// directory, or arbitrary device cannot become a host authority back channel.
// PTYs are held by descriptor; no host /dev/pts pathname is granted.
func linuxCheckStdio(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return errLinuxSeal
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFIFO:
		return nil
	case unix.S_IFCHR:
		if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
			return nil
		}
		if unix.Major(stat.Rdev) == 1 {
			switch unix.Minor(stat.Rdev) {
			case 3, 5, 8, 9: // null, zero, random, urandom
				return nil
			}
		}
	}
	return errLinuxSeal
}

func linuxPinStdio(files [3]*os.File) (pins [3]*os.File, err error) {
	defer func() {
		if err != nil {
			for _, f := range pins {
				if f != nil {
					_ = f.Close()
				}
			}
		}
	}()
	for i, file := range files {
		if file == nil {
			return pins, errLinuxSeal
		}
		raw, rawErr := file.SyscallConn()
		if rawErr != nil {
			return pins, errLinuxSeal
		}
		var operationErr error
		rawErr = raw.Control(func(fd uintptr) {
			operationErr = linuxCheckStdio(int(fd))
			if operationErr != nil {
				return
			}
			copyFD, copyErr := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3)
			operationErr = copyErr
			if copyErr == nil {
				pins[i] = os.NewFile(uintptr(copyFD), "linux-stdio")
			}
		})
		if rawErr != nil || operationErr != nil {
			return pins, errLinuxSeal
		}
	}
	return pins, nil
}

type linuxTerminalState struct {
	file  *os.File
	group int
	attrs unix.Termios
}

// Only an explicitly inherited controlling terminal is admitted. Redirected
// input needs no restoration; no /dev/tty or /dev/pts pathname is reopened.
func linuxCaptureTerminal(file *os.File) (*linuxTerminalState, error) {
	if file == nil {
		return nil, nil
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, errLinuxSettlement
	}
	var state *linuxTerminalState
	var operationErr error
	err = raw.Control(func(fd uintptr) {
		attrs, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
		if errors.Is(err, unix.ENOTTY) {
			return
		}
		if err != nil {
			operationErr = err
			return
		}
		group, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
		if err != nil || group != unix.Getpgrp() {
			operationErr = errLinuxSettlement
			return
		}
		copy, err := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3)
		operationErr = err
		if err == nil {
			state = &linuxTerminalState{os.NewFile(uintptr(copy), "linux-controlling-terminal"), group, *attrs}
		}
	})
	if err != nil || operationErr != nil {
		return nil, errLinuxSettlement
	}
	return state, nil
}

func (s *linuxTerminalState) close() { _ = s.file.Close() }

func (s *linuxTerminalState) restore() (resultErr error) {
	// tcsetpgrp and terminal attribute changes may SIGTTOU a background
	// supervisor. Mask only this locked OS thread, preserving the process's
	// signal disposition and restoring its previous mask on every path.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var blocked, previous unix.Sigset_t
	blocked.Val[(unix.SIGTTOU-1)/64] |= 1 << ((unix.SIGTTOU - 1) % 64)
	if unix.PthreadSigmask(unix.SIG_BLOCK, &blocked, &previous) != nil {
		return errLinuxSettlement
	}
	defer func() {
		if unix.PthreadSigmask(unix.SIG_SETMASK, &previous, nil) != nil {
			resultErr = errLinuxSettlement
		}
	}()
	fd := int(s.file.Fd())
	// TCSETS is immediate; TCSETSW/TCSETSF could block indefinitely on stopped
	// output. Flush before returning foreground ownership, after tree death.
	if unix.IoctlSetTermios(fd, unix.TCSETS, &s.attrs) != nil ||
		unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) != nil ||
		unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, s.group) != nil {
		return errLinuxSettlement
	}
	group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || group != s.group {
		return errLinuxSettlement
	}
	return nil
}

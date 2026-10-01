//go:build darwin

package launch

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Pin inherited terminal descriptors until containment cleanup is proven. A
// literal devfs name is reusable after its last open reference disappears; a
// caller closing its Terminal must not turn the grant into another Session's
// terminal. The copies are CLOEXEC except for their explicit stdio mappings.
func pinSeatbeltTerminal(terminal Terminal) (Terminal, []*os.File, error) {
	var pins []*os.File
	copies := make(map[*os.File]*os.File)
	pin := func(value any) (*os.File, error) {
		file, ok := value.(*os.File)
		if !ok {
			return nil, nil
		}
		if copy, ok := copies[file]; ok {
			return copy, nil
		}
		raw, err := file.SyscallConn()
		if err != nil {
			return nil, err
		}
		var operationErr error
		var duplicate *os.File
		err = raw.Control(func(fd uintptr) {
			var terminal bool
			terminal, operationErr = isSeatbeltTerminalDescriptor(fd)
			if operationErr != nil || !terminal {
				return
			}
			var copyFD int
			copyFD, operationErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
			if operationErr == nil {
				duplicate = os.NewFile(uintptr(copyFD), "acs-inherited-terminal")
			}
		})
		if err != nil || operationErr != nil {
			return nil, errors.Join(err, operationErr)
		}
		if duplicate == nil {
			return file, nil
		}
		copies[file] = duplicate
		pins = append(pins, duplicate)
		return duplicate, nil
	}
	for index, endpoint := range []any{terminal.Input, terminal.Output, terminal.ErrorOutput} {
		file, err := pin(endpoint)
		if err != nil {
			closeSeatbeltTerminalPins(pins)
			return Terminal{}, nil, err
		}
		if file == nil {
			continue
		}
		switch index {
		case 0:
			terminal.Input = file
		case 1:
			terminal.Output = file
		case 2:
			terminal.ErrorOutput = file
		}
	}
	return terminal, pins, nil
}

func closeSeatbeltTerminalPins(pins []*os.File) {
	for _, file := range pins {
		_ = file.Close()
	}
}

func seatbeltTerminalPaths(terminal Terminal) ([]string, error) {
	var paths []string
	seen := make(map[string]bool)
	for _, endpoint := range []any{terminal.Input, terminal.Output, terminal.ErrorOutput} {
		file, ok := endpoint.(*os.File)
		if !ok {
			continue
		}
		raw, err := file.SyscallConn()
		if err != nil {
			return nil, err
		}
		var path string
		var operationErr error
		err = raw.Control(func(fd uintptr) { path, operationErr = seatbeltTerminalDescriptorPath(fd) })
		if err != nil || operationErr != nil {
			return nil, errors.Join(err, operationErr)
		}
		// /dev/tty is a kernel-resolved controlling-terminal alias, not a named
		// device grant. It remains available even with redirected standard streams.
		if path != "" && path != "/dev/tty" && !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}
	return paths, nil
}

func seatbeltTerminalDescriptorPath(fd uintptr) (string, error) {
	terminal, err := isSeatbeltTerminalDescriptor(fd)
	if err != nil || !terminal {
		return "", err
	}
	// F_GETPATH interrogates the opened vnode, never os.File.Name (which is
	// caller-provided) or a symlink spelling. Keep fd locked via RawConn.Control.
	var buffer [unix.PathMax]byte
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])))
	if errno != 0 {
		return "", errno
	}
	length := bytes.IndexByte(buffer[:], 0)
	if length <= 0 {
		return "", errors.New("terminal device path is unavailable")
	}
	path := string(buffer[:length])
	if !validSeatbeltTerminalPath(path) {
		return "", errors.New("unsupported terminal device")
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(fd), &opened); err != nil {
		return "", err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return "", err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFCHR || named.Mode&unix.S_IFMT != unix.S_IFCHR ||
		opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Rdev != named.Rdev || opened.Uid != named.Uid {
		return "", errors.New("terminal device identity changed")
	}
	return path, nil
}

func validSeatbeltTerminalPath(path string) bool {
	if path == "/dev/tty" {
		return true
	}
	suffix, ok := strings.CutPrefix(path, "/dev/ttys")
	if !ok || suffix == "" {
		return false
	}
	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// Only character devices can be terminals. Preserve redirected files, pipes
// and sockets without issuing terminal ioctls or granting their paths.
func isSeatbeltTerminalDescriptor(fd uintptr) (bool, error) {
	var info unix.Stat_t
	if err := unix.Fstat(int(fd), &info); err != nil {
		return false, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFCHR {
		return false, nil
	}
	if _, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA); err != nil {
		// Darwin's /dev/null and other memory devices return ENODEV for
		// unsupported ioctls. Neither result proves a terminal or grants a path.
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENODEV) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

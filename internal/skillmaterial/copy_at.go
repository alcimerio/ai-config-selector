package skillmaterial

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// Every operation accepts a single child name. No path component is resolved
// between the opened parent and the child. os.Root alone is insufficient here:
// its documented contract allows following symlinks within the root.
func validChildName(name string) bool {
	return name != "" && name != "." && name != ".." && !filepath.IsAbs(name) && filepath.Base(name) == name
}

func openAt(parent *os.File, name string, flags int, mode os.FileMode) (*os.File, error) {
	if !validChildName(name) {
		return nil, &os.PathError{Op: "openat", Path: name, Err: os.ErrInvalid}
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, uint32(mode.Perm()))
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func mkdirAt(parent *os.File, name string) error {
	if !validChildName(name) {
		return &os.PathError{Op: "mkdirat", Path: name, Err: os.ErrInvalid}
	}
	err := unix.Mkdirat(int(parent.Fd()), name, 0o700)
	runtime.KeepAlive(parent)
	if err != nil {
		return &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	return nil
}

func readlinkAt(parent *os.File, name string) (string, error) {
	if !validChildName(name) {
		return "", &os.PathError{Op: "readlinkat", Path: name, Err: os.ErrInvalid}
	}
	// This bound exceeds the symlink limits of the supported native filesystem
	// APIs, while avoiding unbounded allocation if the input keeps changing.
	for size := 128; size <= 64*1024; size *= 2 {
		buffer := make([]byte, size)
		n, err := unix.Readlinkat(int(parent.Fd()), name, buffer)
		runtime.KeepAlive(parent)
		if err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: name, Err: err}
		}
		if n < len(buffer) {
			return string(buffer[:n]), nil
		}
	}
	return "", &os.PathError{Op: "readlinkat", Path: name, Err: unix.ENAMETOOLONG}
}

func symlinkAt(parent *os.File, target, name string) error {
	if !validChildName(name) {
		return &os.PathError{Op: "symlinkat", Path: name, Err: os.ErrInvalid}
	}
	err := unix.Symlinkat(target, int(parent.Fd()), name)
	runtime.KeepAlive(parent)
	if err != nil {
		return &os.PathError{Op: "symlinkat", Path: name, Err: err}
	}
	return nil
}

func unlinkAt(parent *os.File, name string) error {
	if !validChildName(name) {
		return &os.PathError{Op: "unlinkat", Path: name, Err: os.ErrInvalid}
	}
	err := unix.Unlinkat(int(parent.Fd()), name, 0)
	runtime.KeepAlive(parent)
	if err != nil {
		return &os.PathError{Op: "unlinkat", Path: name, Err: err}
	}
	return nil
}

package launch

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errLinuxSeal = errors.New("Linux launcher sealing failed")

// Only explicitly supplied stdio crosses the boundary. A connected socket,
// directory, or arbitrary device cannot become a host authority back channel.
// PTYs are held by descriptor; no host /dev/pts pathname is granted. Foreground
// ownership and input flushing belong to the later Session supervisor.
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

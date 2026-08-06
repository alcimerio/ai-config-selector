//go:build darwin

package builder

import "golang.org/x/sys/unix"

func readTerminalAttributes(fileDescriptor int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fileDescriptor, unix.TIOCGETA)
}

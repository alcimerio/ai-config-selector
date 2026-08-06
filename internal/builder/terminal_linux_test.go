//go:build linux

package builder

import "golang.org/x/sys/unix"

func readTerminalAttributes(fileDescriptor int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fileDescriptor, unix.TCGETS)
}

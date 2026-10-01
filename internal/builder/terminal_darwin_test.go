//go:build darwin

package builder

import "golang.org/x/sys/unix"

const terminalAttributesRequest = unix.TIOCGETA

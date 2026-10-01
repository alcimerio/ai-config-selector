//go:build linux

package builder

import "golang.org/x/sys/unix"

const terminalAttributesRequest = unix.TCGETS

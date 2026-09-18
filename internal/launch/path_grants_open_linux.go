//go:build linux

package launch

import "golang.org/x/sys/unix"

func directoryTraversalOpenFlags() int {
	return unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_DIRECTORY
}

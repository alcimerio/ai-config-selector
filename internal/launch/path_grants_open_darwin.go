//go:build darwin

package launch

import "golang.org/x/sys/unix"

// Darwin's O_SEARCH is O_EXEC|O_DIRECTORY. It opens a directory for search
// without requesting read/write directory data, which is required by the
// metadata-only Seatbelt rules for validated ancestors.
func directoryTraversalOpenFlags() int {
	const oExec = 0x40000000
	return oExec | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
}

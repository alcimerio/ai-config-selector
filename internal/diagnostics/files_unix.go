//go:build darwin || linux

package diagnostics

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func readableExecutable(path string) bool { return unix.Access(path, unix.R_OK|unix.X_OK) == nil }
func rootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

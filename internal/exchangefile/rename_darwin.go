//go:build darwin

package exchangefile

import "golang.org/x/sys/unix"

func renameAtNoReplace(directoryFD int, oldName, newName string) error {
	return unix.RenameatxNp(directoryFD, oldName, directoryFD, newName, unix.RENAME_EXCL)
}

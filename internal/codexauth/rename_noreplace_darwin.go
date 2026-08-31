//go:build darwin

package codexauth

import "golang.org/x/sys/unix"

func renameatNoReplace(directoryFD int, oldName, newName string) error {
	return unix.RenameatxNp(directoryFD, oldName, directoryFD, newName, unix.RENAME_EXCL)
}

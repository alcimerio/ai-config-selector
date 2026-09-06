//go:build linux

package codexauthresource

import "golang.org/x/sys/unix"

func renameatNoReplace(directoryFD int, oldName, newName string) error {
	return unix.Renameat2(directoryFD, oldName, directoryFD, newName, unix.RENAME_NOREPLACE)
}

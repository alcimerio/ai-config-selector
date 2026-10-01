// Package skillmaterial owns the target-independent material copy used by common
// Skills and fixed target projections. Bundle descendants are never dereferenced
// through symbolic links; CopyFile has a separate credential-copy contract.
package skillmaterial

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// CopyBundle copies a selected directory, preserving descendant symlinks as
// links. The selected root may itself be a symlink. Once opened, both trees are
// accessed relative to pinned directory descriptors, without following child
// symlinks. Callers must provide a private destination parent and clean up the
// containing Session on failure. This is not a snapshot of concurrently edited
// source files and does not prohibit hard links or mounted filesystems.
func CopyBundle(source, destination string) error {
	destination = filepath.Clean(destination)
	input, err := os.OpenFile(source, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	output, err := os.OpenFile(destination, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer output.Close()
	return copyDirectory(input, output)
}

func copyDirectory(input, output *os.File) error {
	info, err := input.Stat()
	if err != nil {
		return err
	}
	// Preserve directory permissions on the opened destination, without a
	// second path lookup. As before, unwritable directory modes may make the
	// copy fail; callers own cleanup of the containing Session.
	if err := output.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	// Readdir obtains each FileInfo relative to the directory descriptor. In
	// contrast, DirEntry.Info may perform a later, path-based lookup.
	entries, err := input.Readdir(-1)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		switch {
		case entry.IsDir():
			err = copySubdirectory(input, output, entry)
		case entry.Mode()&os.ModeSymlink != 0:
			var target string
			target, err = readlinkAt(input, entry.Name())
			if err == nil {
				err = symlinkAt(output, target, entry.Name())
			}
		case entry.Mode().IsRegular():
			err = copyBundleFile(input, output, entry)
		default:
			err = fmt.Errorf("unsupported file type at %q", entry.Name())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func copySubdirectory(input, output *os.File, entry os.FileInfo) error {
	source, err := openAt(input, entry.Name(), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer source.Close()
	if _, err := validateInput(source, entry); err != nil {
		return err
	}
	if err := mkdirAt(output, entry.Name()); err != nil && !os.IsExist(err) {
		return err
	}
	destination, err := openAt(output, entry.Name(), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer destination.Close()
	return copyDirectory(source, destination)
}

func copyBundleFile(input, output *os.File, entry os.FileInfo) error {
	source, err := openAt(input, entry.Name(), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := validateInput(source, entry)
	if err != nil {
		return err
	}
	return copyRegularFile(source, output, entry.Name(), info.Mode().Perm())
}

// CopyFile copies a regular file, including a symlink-backed credential source.
// It verifies the opened source before creating output and never overwrites an
// existing destination. The destination parent must be private to the caller.
func CopyFile(source, destination string, mode os.FileMode) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source %q is not a regular file", source)
	}
	input, err := os.OpenFile(source, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	if _, err := validateInput(input, info); err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(parent, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer output.Close()
	return copyRegularFile(input, output, filepath.Base(destination), mode)
}

func validateInput(input *os.File, expected os.FileInfo) (os.FileInfo, error) {
	info, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if (!info.Mode().IsRegular() && !info.IsDir()) || info.Mode().Type() != expected.Mode().Type() || !os.SameFile(info, expected) {
		return nil, fmt.Errorf("source %q changed before copying", expected.Name())
	}
	return info, nil
}

func copyRegularFile(input io.Reader, parent *os.File, name string, mode os.FileMode) error {
	output, err := openAt(parent, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	removeIncomplete := true
	defer func() {
		_ = output.Close()
		if removeIncomplete {
			_ = unlinkAt(parent, name)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Chmod(mode); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	removeIncomplete = false
	return nil
}

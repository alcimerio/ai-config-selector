package devin

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func copyBundle(source, destination string) error {
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolvedSource)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source %q is not a directory", source)
	}

	return filepath.WalkDir(resolvedSource, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(resolvedSource, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}

		switch {
		case entry.IsDir():
			if err := os.MkdirAll(target, entryInfo.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, entryInfo.Mode().Perm())
		case entry.Type()&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, target)
		case entry.Type().IsRegular():
			return copyFile(path, target, entryInfo.Mode().Perm())
		default:
			return fmt.Errorf("unsupported file type at %q", path)
		}
	})
}

func copyCredentialIfPresent(source, destination string) error {
	info, err := os.Stat(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("allowlisted credentials path is not a regular file")
	}
	return copyFile(source, destination, 0o600)
}

func copyFile(source, destination string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	removeIncomplete := true
	defer func() {
		_ = output.Close()
		if removeIncomplete {
			_ = os.Remove(destination)
		}
	}()

	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chmod(destination, mode); err != nil {
		return err
	}
	removeIncomplete = false
	return nil
}

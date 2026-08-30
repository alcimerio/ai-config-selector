package codexauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func securePrivateRoot(path string) (string, error) {
	path = filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	root := filepath.Join(parent, filepath.Base(path))
	if err := secureOwnedDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func securePrivateChild(parent, name string) (string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, filepath.Separator) {
		return "", errors.New("invalid private directory name")
	}
	path := filepath.Join(parent, name)
	if err := secureOwnedDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func secureOwnedDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(descriptor), path)
	if directory == nil {
		_ = syscall.Close(descriptor)
		return errors.New("open private directory")
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("invalid private directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory owner")
	}
	return directory.Chmod(0o700)
}

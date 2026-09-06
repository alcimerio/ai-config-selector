package codexauth

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func readPrivateAuthFile(path string) ([]byte, error) {
	contents, err := readPrivateRegularFile(path, maximumAuthJSONSize)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	return contents, nil
}

func readSessionAuthFile(sessionRoot string) ([]byte, error) {
	root, err := openPrivateDirectory(sessionRoot)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer root.Close()
	home, err := openPrivateChildDirectory(root, "home")
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer home.Close()
	codexHome, err := openPrivateChildDirectory(home, ".codex")
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer codexHome.Close()
	descriptor, err := unix.Openat(int(codexHome.Fd()), "auth.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	auth := os.NewFile(uintptr(descriptor), "auth.json")
	if auth == nil {
		_ = unix.Close(descriptor)
		return nil, ErrUnsupportedAuth
	}
	defer auth.Close()
	contents, err := readPrivateRegularDescriptor(auth, maximumAuthJSONSize)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	return contents, nil
}

func openPrivateDirectory(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return privateDirectoryFile(descriptor, path)
}

func openPrivateChildDirectory(parent *os.File, name string) (*os.File, error) {
	descriptor, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return privateDirectoryFile(descriptor, name)
}

func privateDirectoryFile(descriptor int, name string) (*os.File, error) {
	directory := os.NewFile(uintptr(descriptor), name)
	if directory == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private directory")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		_ = directory.Close()
		return nil, errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, errors.New("invalid private directory")
	}
	return directory, nil
}

func readPrivateRegularFile(path string, maximumSize int64) ([]byte, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open private file")
	}
	defer file.Close()
	return readPrivateRegularDescriptor(file, maximumSize)
}

func readPrivateRegularDescriptor(file *os.File, maximumSize int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumSize {
		return nil, errors.New("invalid private file")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return nil, errors.New("invalid private file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > maximumSize {
		clearBytes(contents)
		return nil, errors.New("invalid private file")
	}
	return contents, nil
}

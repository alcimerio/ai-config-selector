package codexauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type fileIdentityLocker struct{ directory string }

type fileIdentityLock struct{ file *os.File }

func newFileIdentityLocker(directory string) *fileIdentityLocker {
	return &fileIdentityLocker{directory: filepath.Clean(directory)}
}

func (locker *fileIdentityLocker) TryLock(name CredentialRef) (identityLock, error) {
	if err := os.MkdirAll(locker.directory, 0o700); err != nil {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	if err := os.Chmod(locker.directory, 0o700); err != nil {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	directoryInfo, err := os.Lstat(locker.directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	path := filepath.Join(locker.directory, string(name)+".lock")
	descriptor, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %q", ErrIdentityBusy, name)
		}
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	return &fileIdentityLock{file: file}, nil
}

func (locked *fileIdentityLock) Release() error {
	if locked == nil || locked.file == nil {
		return nil
	}
	file := locked.file
	locked.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

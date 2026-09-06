package codexauth

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type fileIdentityLocker struct {
	directory *privateDirectory
	initErr   error
}

type fileIdentityLock struct{ file *os.File }

type lockDescriptorMetadata struct {
	regular bool
	owner   uint32
	links   uint64
}

func newFileIdentityLocker(directory string) *fileIdentityLocker {
	pinned, err := pinPrivateDirectory(directory)
	return &fileIdentityLocker{directory: pinned, initErr: err}
}

func (locker *fileIdentityLocker) TryLock(name CredentialRef) (identityLock, error) {
	if locker == nil || locker.initErr != nil {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	file, err := locker.directory.open(string(name)+".lock", unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock Codex authentication identity %q: %w", name, ErrProviderUnavailable)
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || validateLockDescriptorMetadata(lockDescriptorMetadata{
		regular: info.Mode().IsRegular(),
		owner:   native.Uid,
		links:   uint64(native.Nlink),
	}, uint32(os.Geteuid())) != nil {
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

func validateLockDescriptorMetadata(metadata lockDescriptorMetadata, effectiveUID uint32) error {
	if !metadata.regular || metadata.owner != effectiveUID || metadata.links != 1 {
		return ErrProviderUnavailable
	}
	return nil
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

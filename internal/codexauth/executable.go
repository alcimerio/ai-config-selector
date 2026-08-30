package codexauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// pinnedExecutable resolves one operation-scoped Codex executable lazily and
// rejects path or file replacement before every subprocess.
type pinnedExecutable struct {
	configured string

	mutex     sync.Mutex
	canonical string
	identity  os.FileInfo
	digest    [sha256.Size]byte
}

func newPinnedExecutable(configured string) *pinnedExecutable {
	return &pinnedExecutable{configured: configured}
}

func (executable *pinnedExecutable) Resolve() (string, error) {
	if executable == nil || executable.configured == "" {
		return "", errors.New("Codex executable is required")
	}

	executable.mutex.Lock()
	defer executable.mutex.Unlock()

	if executable.canonical == "" {
		resolved := executable.configured
		if !strings.ContainsRune(resolved, filepath.Separator) {
			path, err := exec.LookPath(resolved)
			if err != nil {
				return "", err
			}
			resolved = path
		}
		absolute, err := filepath.Abs(resolved)
		if err != nil {
			return "", err
		}
		canonical, err := filepath.EvalSymlinks(filepath.Clean(absolute))
		if err != nil {
			return "", err
		}
		identity, digest, err := inspectExecutable(canonical)
		if err != nil {
			return "", err
		}
		executable.canonical = canonical
		executable.identity = identity
		executable.digest = digest
		return canonical, nil
	}

	current, digest, err := inspectExecutable(executable.canonical)
	if err != nil || !os.SameFile(executable.identity, current) ||
		executable.identity.Mode() != current.Mode() ||
		executable.identity.Size() != current.Size() ||
		!executable.identity.ModTime().Equal(current.ModTime()) ||
		subtle.ConstantTimeCompare(executable.digest[:], digest[:]) != 1 {
		return "", errors.New("Codex executable changed after preflight")
	}
	return executable.canonical, nil
}

// Snapshot copies the pinned bytes into a private directory outside the
// writable Session and workspace. Both contained subprocesses execute this
// single immutable operation-scoped path.
func (executable *pinnedExecutable) Snapshot(snapshotRoot string) (string, func(), error) {
	if _, err := executable.Resolve(); err != nil {
		return "", nil, err
	}

	executable.mutex.Lock()
	defer executable.mutex.Unlock()

	if err := secureExecutableSnapshotRoot(snapshotRoot); err != nil {
		return "", nil, err
	}
	directory, err := os.MkdirTemp(snapshotRoot, "operation-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	if err := os.Chmod(directory, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}

	source, current, err := openExecutable(executable.canonical)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer source.Close()
	if !sameExecutable(executable.identity, current) {
		cleanup()
		return "", nil, errors.New("Codex executable changed after preflight")
	}

	path := filepath.Join(directory, "codex")
	destination, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	digest := hash.Sum(nil)
	if copyErr != nil || syncErr != nil || closeErr != nil ||
		subtle.ConstantTimeCompare(executable.digest[:], digest) != 1 {
		cleanup()
		return "", nil, errors.New("Codex executable changed while snapshotting")
	}
	if err := syncExecutableDirectory(directory); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func secureExecutableSnapshotRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid Codex executable snapshot directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid Codex executable snapshot directory")
	}
	return os.Chmod(path, 0o700)
}

func executableSnapshotRoot(config codexLoginConfig) (string, error) {
	sessions, err := filepath.EvalSymlinks(config.SessionsDirectory)
	if err != nil {
		return "", err
	}
	workspace, err := filepath.EvalSymlinks(config.WorkingDirectory)
	if err != nil {
		return "", err
	}
	root := sessions + ".executables"
	if pathsOverlap(workspace, root) {
		return "", errors.New("Codex executable snapshot overlaps the writable workspace")
	}
	return root, nil
}

func pathsOverlap(left, right string) bool {
	within := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return within(left, right) || within(right, left)
}

func inspectExecutable(path string) (os.FileInfo, [sha256.Size]byte, error) {
	file, info, err := openExecutable(path)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return info, digest, nil
}

func openExecutable(path string) (*os.File, os.FileInfo, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, nil, errors.New("open Codex executable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		_ = file.Close()
		return nil, nil, errors.New("Codex executable is not an executable regular file")
	}
	return file, info, nil
}

func sameExecutable(want, current os.FileInfo) bool {
	return os.SameFile(want, current) && want.Mode() == current.Mode() &&
		want.Size() == current.Size() && want.ModTime().Equal(current.ModTime())
}

func syncExecutableDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

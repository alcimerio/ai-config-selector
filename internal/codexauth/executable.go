package codexauth

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// pinnedExecutable resolves one operation-scoped Codex executable lazily and
// rejects path or file replacement before every subprocess.
type pinnedExecutable struct {
	configured string

	mutex     sync.Mutex
	canonical string
	identity  os.FileInfo
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
		identity, err := validExecutableInfo(canonical)
		if err != nil {
			return "", err
		}
		executable.canonical = canonical
		executable.identity = identity
		return canonical, nil
	}

	current, err := validExecutableInfo(executable.canonical)
	if err != nil || !os.SameFile(executable.identity, current) ||
		executable.identity.Mode() != current.Mode() ||
		executable.identity.Size() != current.Size() ||
		!executable.identity.ModTime().Equal(current.ModTime()) {
		return "", errors.New("Codex executable changed after preflight")
	}
	return executable.canonical, nil
}

func validExecutableInfo(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("Codex executable is not an executable regular file")
	}
	return info, nil
}

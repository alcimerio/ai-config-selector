package executor

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
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

	mutex             sync.Mutex
	canonical         string
	identity          os.FileInfo
	digest            [sha256.Size]byte
	companionSet      bool
	companion         string
	companionIdentity os.FileInfo
	companionDigest   [sha256.Size]byte
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
		canonical, err := resolveConfiguredExecutable(executable.configured)
		if err != nil {
			return "", err
		}
		identity, digest, err := inspectExecutable(canonical)
		if err != nil {
			return "", err
		}
		companion, companionIdentity, companionDigest, companionErr := resolveCodeModeCompanion(canonical)
		if companionErr != nil {
			return "", companionErr
		}
		executable.canonical = canonical
		executable.identity = identity
		executable.digest = digest
		executable.companionSet = true
		executable.companion, executable.companionIdentity, executable.companionDigest = companion, companionIdentity, companionDigest
		return canonical, nil
	}

	canonical, err := resolveConfiguredExecutable(executable.configured)
	if err != nil || canonical != executable.canonical {
		return "", errors.New("Codex executable changed after preflight")
	}
	current, digest, err := inspectExecutable(executable.canonical)
	if err != nil || !os.SameFile(executable.identity, current) ||
		executable.identity.Mode() != current.Mode() ||
		executable.identity.Size() != current.Size() ||
		!executable.identity.ModTime().Equal(current.ModTime()) ||
		subtle.ConstantTimeCompare(executable.digest[:], digest[:]) != 1 {
		return "", errors.New("Codex executable changed after preflight")
	}
	if executable.companionSet {
		currentCompanion, info, digest, companionErr := resolveCodeModeCompanion(canonical)
		if companionErr != nil {
			return "", companionErr
		}
		if currentCompanion != executable.companion || (currentCompanion != "" && (info == nil || executable.companionIdentity == nil || !sameExecutable(executable.companionIdentity, info) || subtle.ConstantTimeCompare(executable.companionDigest[:], digest[:]) != 1)) {
			return "", errors.New("Codex code-mode host changed after preflight")
		}
	}
	return executable.canonical, nil
}

func resolveCodeModeCompanion(canonical string) (string, os.FileInfo, [sha256.Size]byte, error) {
	const name = "codex-code-mode-host"
	exeDir := filepath.Dir(canonical)
	packageDir, binDir := "", ""
	// Pinned InstallContext recognizes bin/ and codex-resources/ entrypoints
	// only when the corresponding bin directory and package marker exist.
	if base := filepath.Base(exeDir); base == "bin" || base == "codex-resources" {
		root := filepath.Dir(exeDir)
		bin := filepath.Join(root, "bin")
		validBin, err := companionDirectory(bin)
		if err != nil {
			return "", nil, [sha256.Size]byte{}, err
		}
		if validBin {
			metadata, err := packageMetadata(filepath.Join(root, "codex-package.json"))
			if err != nil {
				return "", nil, [sha256.Size]byte{}, err
			}
			if metadata {
				packageDir, binDir = root, bin
			}
		}
	}

	// Build the complete pinned order before selecting a file: package resource,
	// legacy standalone resource, package bin (or release/executable directory),
	// then the executable sibling. Legacy release identity uses the package root
	// when a package was recognized, never a fabricated bin/codex-resources tree.
	candidates := make([]string, 0, 4)
	addResources := func(root string) error {
		directory := filepath.Join(root, "codex-resources")
		exists, err := companionDirectory(directory)
		if err != nil {
			return err
		}
		if exists {
			candidates = append(candidates, filepath.Join(directory, name))
		}
		return nil
	}
	if packageDir != "" {
		if err := addResources(packageDir); err != nil {
			return "", nil, [sha256.Size]byte{}, err
		}
	}
	releaseDir := exeDir
	if packageDir != "" {
		releaseDir = packageDir
	}
	standalone := legacyStandaloneReleaseDir(releaseDir)
	if standalone {
		if err := addResources(releaseDir); err != nil {
			return "", nil, [sha256.Size]byte{}, err
		}
	}
	preferredDir := exeDir
	if packageDir != "" {
		preferredDir = binDir
	} else if standalone {
		preferredDir = releaseDir
	}
	candidates = append(candidates, filepath.Join(preferredDir, name), filepath.Join(exeDir, name))

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if _, err := os.Lstat(candidate); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", nil, [sha256.Size]byte{}, fmt.Errorf("inspect Codex code-mode host %s: %w", candidate, err)
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", nil, [sha256.Size]byte{}, fmt.Errorf("resolve Codex code-mode host %s: %w", candidate, err)
		}
		info, digest, err := inspectExecutable(resolved)
		if err != nil {
			return "", nil, [sha256.Size]byte{}, fmt.Errorf("inspect Codex code-mode host %s: %w", candidate, err)
		}
		return resolved, info, digest, nil
	}
	return "", nil, [sha256.Size]byte{}, nil
}

// Optional layout directories must really be directories. Unexpected access or
// traversal errors remain refusals rather than silently selecting another file.
func companionDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Codex companion directory %s: %w", path, err)
	}
	return info.IsDir(), nil
}

func packageMetadata(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Codex package metadata %s: %w", path, err)
	}
	return info.Mode().IsRegular(), nil
}

func legacyStandaloneReleaseDir(releaseDir string) bool {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		home = filepath.Join(userHome, ".codex")
	}
	// Upstream find_codex_home validates/canonicalizes explicit CODEX_HOME,
	// and standalone_install_method canonicalizes even the default. Failure
	// removes only legacy-install recognition (from_exe uses .ok()), not the
	// independent package/sibling lookup. Never use an uncanonical fallback.
	canonicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return false
	}
	info, err := os.Stat(canonicalHome)
	if err != nil || !info.IsDir() {
		return false
	}
	canonicalHome, err = filepath.Abs(canonicalHome)
	if err != nil {
		return false
	}
	releasesRoot := filepath.Join(canonicalHome, "packages", "standalone", "releases")
	relative, err := filepath.Rel(releasesRoot, releaseDir)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolveConfiguredExecutable(configured string) (string, error) {
	resolved := configured
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
	return filepath.EvalSymlinks(filepath.Clean(absolute))
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
	if executable.companion != "" {
		if err := copyPinnedCompanion(executable.companion, filepath.Join(directory, "codex-code-mode-host"), executable.companionIdentity, executable.companionDigest); err != nil {
			cleanup()
			return "", nil, err
		}
		if err := syncExecutableDirectory(directory); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return path, cleanup, nil
}

func copyPinnedCompanion(sourcePath, destinationPath string, want os.FileInfo, wantDigest [sha256.Size]byte) error {
	source, current, err := openExecutable(sourcePath)
	if err != nil || !sameExecutable(want, current) {
		if source != nil {
			_ = source.Close()
		}
		return errors.New("Codex code-mode host changed while snapshotting")
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	digest := hash.Sum(nil)
	if copyErr != nil || syncErr != nil || closeErr != nil || subtle.ConstantTimeCompare(wantDigest[:], digest) != 1 {
		_ = os.Remove(destinationPath)
		return errors.New("Codex code-mode host changed while copying")
	}
	return nil
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
	sessionsParent, err := filepath.EvalSymlinks(filepath.Dir(config.SessionsDirectory))
	if err != nil {
		return "", err
	}
	sessions := filepath.Join(sessionsParent, filepath.Base(config.SessionsDirectory))
	if info, statErr := os.Lstat(sessions); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("invalid Sessions directory")
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
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
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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

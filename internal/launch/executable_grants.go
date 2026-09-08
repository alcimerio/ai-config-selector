package launch

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"golang.org/x/sys/unix"
)

var executableSearchPath = runcommand.FixedSearchPath

// ResolveExecutableGrants resolves visibility entries independently of the
// primary command. Fixed-search references use ACS's constant search order;
// host PATH is never consulted.
func ResolveExecutableGrants(intents []ExecutableGrantIntent, workspace, sessionsDirectory string, suppliedProtected ...[]string) ([]ExecutableGrant, error) {
	canonicalWorkspace, err := resolveExistingPath(workspace, true, false)
	if err != nil {
		return nil, err
	}
	canonicalSessions, err := resolveFuturePath(sessionsDirectory)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("user home is unavailable")
	}
	canonicalHome, err := filepath.EvalSymlinks(filepath.Clean(home))
	if err != nil {
		return nil, errors.New("user home is unavailable")
	}
	protectedInputs := []string{canonicalSessions}
	if len(suppliedProtected) != 0 {
		protectedInputs = append(protectedInputs, suppliedProtected[0]...)
	}
	protected, err := resolveProtectedPaths(protectedInputs)
	if err != nil {
		return nil, err
	}

	result := make([]ExecutableGrant, 0, len(intents))
	for _, intent := range intents {
		candidate := ""
		switch intent.ReferenceKind {
		case ExecutableReferenceFixedSearchName:
			candidate = fixedSearchExecutable(intent.Name)
			if candidate == "" {
				return nil, errors.New("selected executable is unavailable")
			}
		case ExecutableReferenceWorkspaceRelative:
			candidate = filepath.Join(canonicalWorkspace, filepath.FromSlash(intent.Path))
		case ExecutableReferenceLocalAbsolute:
			candidate = filepath.Clean(intent.Path)
		default:
			return nil, errors.New("unsupported executable reference")
		}
		canonical, logicalWitness, identity, digest, err := inspectExecutableGrant(candidate)
		if err != nil {
			return nil, err
		}
		switch intent.ReferenceKind {
		case ExecutableReferenceWorkspaceRelative:
			if !withinOrEqual(canonicalWorkspace, canonical) {
				return nil, errors.New("workspace-relative executable escapes its anchor")
			}
		case ExecutableReferenceLocalAbsolute:
			if !supportedExecutableLogicalRoot(canonicalHome, candidate, canonicalWorkspace) {
				return nil, errors.New("local executable is outside supported roots")
			}
		}
		for _, denied := range protected {
			if pathsOverlap(canonical, denied.path) || (denied.exists && identity.device == denied.identity.device && identity.inode == denied.identity.inode) {
				return nil, errors.New("executable overlaps protected private state")
			}
		}
		grant := ExecutableGrant{ID: intent.ID, ReferenceKind: intent.ReferenceKind, searchName: intent.Name, logicalPath: filepath.Clean(candidate), logicalWitness: logicalWitness, path: canonical, identity: identity, digest: digest}
		if intent.ReferenceKind == ExecutableReferenceWorkspaceRelative {
			workspacePath, workspaceWitness, workspaceIdentity, inspectErr := inspectGrantPath(filepath.Clean(workspace), PathTypeDirectory, PathAccessReadOnly)
			if inspectErr != nil || workspacePath != canonicalWorkspace {
				return nil, errors.New("workspace identity changed")
			}
			grant.workspaceRelative = true
			grant.workspaceLogicalPath = filepath.Clean(workspace)
			grant.workspaceLogicalWitness = workspaceWitness
			grant.workspacePath = workspacePath
			grant.workspaceIdentity = workspaceIdentity
		}
		result = append(result, grant)
	}
	return result, nil
}

func fixedSearchExecutable(name string) string {
	for _, directory := range strings.Split(executableSearchPath, string(os.PathListSeparator)) {
		candidate := filepath.Join(directory, name)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

func supportedExecutableLogicalRoot(home, logical, workspace string) bool {
	cleaned := filepath.Clean(logical)
	if withinOrEqual(workspace, cleaned) || supportedLocalGrantRoot(home, cleaned) {
		return true
	}
	for _, root := range strings.Split(runcommand.FixedSearchPath, string(os.PathListSeparator)) {
		if withinOrEqual(root, cleaned) {
			return true
		}
	}
	return false
}

func inspectExecutableGrant(candidate string) (string, []pathIdentity, pathIdentity, [sha256.Size]byte, error) {
	clean := filepath.Clean(candidate)
	witness, err := inspectLogicalComponents(clean)
	if err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	canonical, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unavailable")
	}
	fd, err := openCanonicalPath(canonical, PathTypeFile)
	if err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	file := os.NewFile(uintptr(fd), "selected executable")
	if file == nil {
		_ = unix.Close(fd)
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	identity := identityFromFileInfo(info, stat)
	if identity.mode.Perm()&0o111 == 0 {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is not executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	after, err := file.Stat()
	if err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable is unsafe")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || identityFromFileInfo(after, afterStat) != identity {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, errors.New("selected executable changed during read")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return canonical, witness, identity, digest, nil
}

func revalidateExecutableGrants(grants []ExecutableGrant, workspace, sessions string) ([]ExecutableGrant, error) {
	result := append([]ExecutableGrant(nil), grants...)
	for _, grant := range result {
		if grant.ReferenceKind == ExecutableReferenceFixedSearchName {
			selected := fixedSearchExecutable(grant.searchName)
			if selected == "" || filepath.Clean(selected) != grant.logicalPath {
				return nil, errors.New("selected executable search result changed")
			}
		}
		if grant.workspaceRelative {
			canonical, witness, identity, err := inspectGrantPath(filepath.Clean(workspace), PathTypeDirectory, PathAccessReadOnly)
			if err != nil || filepath.Clean(workspace) != grant.workspaceLogicalPath || canonical != grant.workspacePath || identity != grant.workspaceIdentity || !equalPathWitness(witness, grant.workspaceLogicalWitness) {
				return nil, errors.New("workspace identity changed")
			}
		}
		canonical, witness, identity, digest, err := inspectExecutableGrant(grant.logicalPath)
		if err != nil || canonical != grant.path || identity != grant.identity || digest != grant.digest || !equalPathWitness(witness, grant.logicalWitness) {
			return nil, errors.New("selected executable identity changed")
		}
		if pathsOverlap(canonical, sessions) || pathsOverlap(canonical, SessionOperationsDirectory(sessions)) {
			return nil, errors.New("executable overlaps protected private state")
		}
	}
	return result, nil
}

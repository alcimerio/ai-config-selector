package launch

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

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
		inspected, err := inspectExecutableGrantReusing(candidate, nil)
		canonical, logicalWitness, identity, digest := inspected.path, inspected.witness, inspected.identity, inspected.digest
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
		grant := ExecutableGrant{ID: intent.ID, ReferenceKind: intent.ReferenceKind, searchName: intent.Name, logicalPath: filepath.Clean(candidate), logicalWitness: logicalWitness, path: canonical, identity: identity, digest: digest, changedNanos: inspected.changedNanos, digestReusable: inspected.digestReusable}
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
	inspected, err := inspectExecutableGrantReusing(candidate, nil)
	if err != nil {
		return "", nil, pathIdentity{}, [sha256.Size]byte{}, err
	}
	return inspected.path, inspected.witness, inspected.identity, inspected.digest, nil
}

type inspectedExecutable struct {
	path         string
	witness      []pathIdentity
	identity     pathIdentity
	digest       [sha256.Size]byte
	changedNanos int64
	// digestReusable is true only when ctime was already older than
	// executableDigestReuseMargin when the digest was computed.
	digestReusable bool
}

// executableDigestReuseMargin is how much older than the hash itself an
// executable's ctime must be before the digest may be reused. Kernels stamp
// ctime from a coarse clock (one scheduler tick on Linux), so a write landing
// in the same tick as the hash could leave ctime unchanged. Like Git's "racy
// index" rule, a recently changed file is simply re-hashed every time.
var executableDigestReuseMargin = time.Second

// executableDigestReads counts full SHA-256 reads of executables. Tests use it
// to prove that revalidation within one launch does not re-hash.
var executableDigestReads atomic.Int64

// inspectExecutableGrantReusing inspects candidate like inspectExecutableGrant.
// When previous is non-nil and the opened file still has the same canonical
// path, identity (device, inode, mode, links, size, mtime) and ctime that were
// recorded when previous.digest was computed, the digest is reused instead of
// re-reading the whole executable. Any content change advances ctime (and
// mtime, size or inode), so a modified or replaced executable is re-hashed and
// then rejected by the caller's digest comparison.
func inspectExecutableGrantReusing(candidate string, previous *ExecutableGrant) (inspectedExecutable, error) {
	clean := filepath.Clean(candidate)
	witness, err := inspectLogicalComponents(clean)
	if err != nil {
		return inspectedExecutable{}, pathInspectionError("selected executable is unsafe", err)
	}
	canonical, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return inspectedExecutable{}, errors.New("selected executable is unavailable")
	}
	fd, err := openCanonicalPath(canonical, PathTypeFile)
	if err != nil {
		return inspectedExecutable{}, pathInspectionError("selected executable is unsafe", err)
	}
	file := os.NewFile(uintptr(fd), "selected executable")
	if file == nil {
		_ = unix.Close(fd)
		return inspectedExecutable{}, errors.New("selected executable is unsafe")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return inspectedExecutable{}, errors.New("selected executable is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return inspectedExecutable{}, errors.New("selected executable is unsafe")
	}
	identity := identityFromFileInfo(info, stat)
	if identity.mode.Perm()&0o111 == 0 {
		return inspectedExecutable{}, errors.New("selected executable is not executable")
	}
	changed := statChangeNanos(stat)
	if previous != nil && previous.digestReusable && previous.path == canonical && previous.identity == identity && previous.changedNanos == changed {
		return inspectedExecutable{path: canonical, witness: witness, identity: identity, digest: previous.digest, changedNanos: changed, digestReusable: true}, nil
	}
	hashedAt := time.Now()
	executableDigestReads.Add(1)
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return inspectedExecutable{}, errors.New("selected executable is unsafe")
	}
	after, err := file.Stat()
	if err != nil {
		return inspectedExecutable{}, errors.New("selected executable is unsafe")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || identityFromFileInfo(after, afterStat) != identity || statChangeNanos(afterStat) != changed {
		return inspectedExecutable{}, errors.New("selected executable changed during read")
	}
	reusable := changed < hashedAt.Add(-executableDigestReuseMargin).UnixNano()
	result := inspectedExecutable{path: canonical, witness: witness, identity: identity, changedNanos: changed, digestReusable: reusable}
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}

func revalidateExecutableGrants(grants []ExecutableGrant, workspace, sessions string) ([]ExecutableGrant, error) {
	result := append([]ExecutableGrant(nil), grants...)
	for index := range result {
		grant := &result[index]
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
		inspected, err := inspectExecutableGrantReusing(grant.logicalPath, grant)
		canonical, witness, identity, digest := inspected.path, inspected.witness, inspected.identity, inspected.digest
		if err != nil || canonical != grant.path || identity != grant.identity || digest != grant.digest || !equalPathWitness(witness, grant.logicalWitness) {
			return nil, errors.New("selected executable identity changed")
		}
		if pathsOverlap(canonical, sessions) || pathsOverlap(canonical, SessionOperationsDirectory(sessions)) {
			return nil, errors.New("executable overlaps protected private state")
		}
	}
	return result, nil
}

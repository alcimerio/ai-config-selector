package launch

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type pathIdentity struct {
	device, inode uint64
	mode          os.FileMode
	links         uint64
	size          int64
	modifiedNanos int64
}

func ResolveFilesystemGrants(intents []PathGrantIntent, workspace, sessionsDirectory string, workspaceAccess WorkspaceAccess, suppliedProtected ...[]string) ([]FilesystemGrant, error) {
	canonicalWorkspace, err := resolveExistingPath(workspace, true, false)
	if err != nil {
		return nil, err
	}
	var (
		workspaceLogicalPath    string
		workspaceLogicalWitness []pathIdentity
		workspaceIdentity       pathIdentity
	)
	for _, intent := range intents {
		if intent.ReferenceKind != PathReferenceWorkspaceRelative {
			continue
		}
		workspaceLogicalPath = filepath.Clean(workspace)
		inspectedWorkspace, witness, identity, inspectErr := inspectGrantPath(workspaceLogicalPath, PathTypeDirectory, PathAccessReadOnly)
		if inspectErr != nil || inspectedWorkspace != canonicalWorkspace {
			return nil, errors.New("workspace identity changed")
		}
		workspaceLogicalWitness, workspaceIdentity = witness, identity
		break
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
	var protectedWritable []protectedPath
	hasWritableIntent := false
	for _, intent := range intents {
		hasWritableIntent = hasWritableIntent || intent.Access == PathAccessReadWrite
	}
	if hasWritableIntent && len(suppliedProtected) > 1 {
		protectedWritable, err = resolveProtectedPaths(suppliedProtected[1])
		if err != nil {
			return nil, err
		}
	}
	for _, denied := range protected {
		if pathsOverlap(canonicalWorkspace, denied.path) {
			return nil, errors.New("workspace overlaps protected private state")
		}
	}
	grants := make([]FilesystemGrant, 0, len(intents))
	for _, intent := range intents {
		var candidate string
		switch intent.ReferenceKind {
		case PathReferenceWorkspaceRelative:
			candidate = filepath.Join(canonicalWorkspace, filepath.FromSlash(intent.Path))
		case PathReferenceLocalAbsolute:
			candidate = filepath.Clean(intent.Path)
		default:
			return nil, errors.New("unsupported path reference")
		}
		canonical, logicalWitness, identity, err := inspectGrantPath(candidate, intent.Type, intent.Access)
		if err != nil {
			return nil, err
		}
		if intent.ReferenceKind == PathReferenceWorkspaceRelative && !withinOrEqual(canonicalWorkspace, canonical) {
			return nil, errors.New("workspace-relative path escapes its anchor")
		}
		if intent.ReferenceKind == PathReferenceLocalAbsolute && !supportedLocalGrantRoot(canonicalHome, canonical) {
			return nil, errors.New("local path is outside supported roots")
		}
		for _, denied := range protected {
			if pathsOverlap(canonical, denied.path) || (intent.Type == PathTypeFile && denied.exists && identity.device == denied.identity.device && identity.inode == denied.identity.inode) {
				return nil, errors.New("path overlaps protected private state")
			}
		}
		if intent.Access == PathAccessReadWrite && protectedWritableRoot(canonical) {
			return nil, errors.New("writable path overlaps a protected system root")
		}
		if intent.Access == PathAccessReadWrite {
			for _, denied := range protectedWritable {
				if pathsOverlap(canonical, denied.path) || (intent.Type == PathTypeFile && denied.exists && identity.device == denied.identity.device && identity.inode == denied.identity.inode) {
					return nil, errors.New("writable path overlaps a registered runtime input")
				}
			}
		}
		grant := FilesystemGrant{ID: intent.ID, Access: intent.Access, Type: intent.Type, logicalPath: filepath.Clean(candidate), logicalWitness: logicalWitness, path: canonical, identity: identity, effective: true}
		if intent.ReferenceKind == PathReferenceWorkspaceRelative {
			grant.workspaceRelative = true
			grant.workspaceLogicalPath = workspaceLogicalPath
			grant.workspaceLogicalWitness = append([]pathIdentity(nil), workspaceLogicalWitness...)
			grant.workspacePath = canonicalWorkspace
			grant.workspaceIdentity = workspaceIdentity
		}
		grants = append(grants, grant)
	}
	return reduceFilesystemGrants(grants, canonicalWorkspace, workspaceAccess), nil
}

type protectedPath struct {
	path     string
	exists   bool
	identity pathIdentity
}

func resolveProtectedPaths(inputs []string) ([]protectedPath, error) {
	result := make([]protectedPath, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		if input == "" || !filepath.IsAbs(input) {
			return nil, errors.New("protected path is invalid")
		}
		canonical, err := filepath.EvalSymlinks(filepath.Clean(input))
		entry := protectedPath{exists: err == nil}
		if err == nil {
			entry.path = canonical
			info, statErr := os.Stat(canonical)
			if statErr != nil {
				return nil, errors.New("protected path is unavailable")
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				entry.identity = identityFromFileInfo(info, stat)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			entry.path, err = resolveFuturePath(input)
			if err != nil {
				return nil, errors.New("protected path is unsafe")
			}
		} else {
			return nil, errors.New("protected path is unsafe")
		}
		if !seen[entry.path] {
			seen[entry.path] = true
			result = append(result, entry)
		}
	}
	return result, nil
}

func supportedLocalGrantRoot(home, candidate string) bool {
	if pathWithin(home, candidate) {
		return true
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(candidate), string(filepath.Separator)), string(filepath.Separator))
	if len(components) < 3 || components[0] != "Volumes" || components[1] == "" {
		return false
	}
	volume := filepath.Join(string(filepath.Separator), components[0], components[1])
	volumeInfo, err := os.Stat(volume)
	if err != nil || !volumeInfo.IsDir() {
		return false
	}
	parentInfo, err := os.Stat(filepath.Dir(volume))
	if err != nil {
		return false
	}
	volumeStat, vok := volumeInfo.Sys().(*syscall.Stat_t)
	parentStat, pok := parentInfo.Sys().(*syscall.Stat_t)
	return vok && pok && volumeStat.Dev != parentStat.Dev
}

func protectedWritableRoot(candidate string) bool {
	for _, root := range []string{"/System", "/Library", "/private", "/dev", "/usr", "/bin", "/sbin"} {
		if candidate == root || pathWithin(root, candidate) {
			return true
		}
	}
	return false
}

func inspectGrantPath(path string, want PathType, access PathAccess) (string, []pathIdentity, pathIdentity, error) {
	logicalWitness, err := inspectLogicalComponents(filepath.Clean(path))
	if err != nil {
		return "", nil, pathIdentity{}, errors.New("selected path is unsafe")
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", nil, pathIdentity{}, errors.New("selected path is unavailable")
	}
	fd, err := openCanonicalPath(canonical, want)
	if err != nil {
		return "", nil, pathIdentity{}, errors.New("selected path is unsafe")
	}
	file := os.NewFile(uintptr(fd), "selected path")
	if file == nil {
		unix.Close(fd)
		return "", nil, pathIdentity{}, errors.New("selected path is unsafe")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, pathIdentity{}, errors.New("selected path is unsafe")
	}
	if (want == PathTypeDirectory && !info.IsDir()) || (want == PathTypeFile && !info.Mode().IsRegular()) {
		return "", nil, pathIdentity{}, errors.New("selected path has the wrong type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil, pathIdentity{}, errors.New("selected path identity is unavailable")
	}
	if access == PathAccessReadWrite && want == PathTypeFile && stat.Nlink != 1 {
		return "", nil, pathIdentity{}, errors.New("writable file must have one link")
	}
	return canonical, logicalWitness, identityFromFileInfo(info, stat), nil
}

func identityFromFileInfo(info os.FileInfo, stat *syscall.Stat_t) pathIdentity {
	identity := pathIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), mode: info.Mode()}
	if info.Mode().IsRegular() {
		identity.links = uint64(stat.Nlink)
		identity.size = info.Size()
		identity.modifiedNanos = info.ModTime().UnixNano()
	}
	return identity
}

func inspectLogicalComponents(path string) ([]pathIdentity, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path must be absolute")
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	prefix := string(filepath.Separator)
	result := make([]pathIdentity, 0, len(components))
	for index, component := range components {
		var stat unix.Stat_t
		if err := unix.Fstatat(current, component, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		// Directory link counts change when an unrelated sibling directory is
		// created or removed. Logical traversal identity is the component's
		// device, inode, and type/mode; final regular-file witnesses separately
		// retain link count, size, and mtime.
		witness := pathIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), mode: os.FileMode(stat.Mode)}
		result = append(result, witness)
		logicalComponent := filepath.Join(prefix, component)
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			resolved, err := filepath.EvalSymlinks(logicalComponent)
			if err != nil {
				return nil, err
			}
			var after unix.Stat_t
			if err := unix.Fstatat(current, component, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(after.Dev) != witness.device || uint64(after.Ino) != witness.inode || os.FileMode(after.Mode) != witness.mode {
				return nil, errors.New("logical symlink changed during resolution")
			}
			prefix = resolved
			if index == len(components)-1 {
				continue
			}
			next, err := openCanonicalPath(resolved, PathTypeDirectory)
			if err != nil {
				return nil, errors.New("symlink target is not a directory")
			}
			if err := unix.Close(current); err != nil {
				_ = unix.Close(next)
				return nil, err
			}
			current = next
			continue
		}
		prefix = logicalComponent
		if index < len(components)-1 {
			next, err := unix.Openat(current, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_DIRECTORY, 0)
			if err != nil {
				return nil, errors.New("path parent is not a directory")
			}
			if err := unix.Close(current); err != nil {
				_ = unix.Close(next)
				return nil, err
			}
			current = next
		}
	}
	return result, nil
}

func openCanonicalPath(path string, want PathType) (int, error) {
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	if len(components) == 1 && components[0] == "" {
		return current, nil
	}
	for index, component := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if index < len(components)-1 || want == PathTypeDirectory {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(current, component, flags, 0)
		if err != nil {
			_ = unix.Close(current)
			return -1, err
		}
		if err := unix.Close(current); err != nil {
			_ = unix.Close(next)
			return -1, err
		}
		current = next
	}
	return current, nil
}

func revalidateFilesystemGrants(grants []FilesystemGrant, workspace, sessions string) ([]FilesystemGrant, error) {
	result := append([]FilesystemGrant(nil), grants...)
	var (
		workspaceInspected bool
		logicalWorkspace   string
		canonicalWorkspace string
		workspaceWitness   []pathIdentity
		workspaceIdentity  pathIdentity
		workspaceErr       error
	)
	for _, grant := range result {
		if !grant.workspaceRelative {
			continue
		}
		if !workspaceInspected {
			workspaceInspected = true
			logicalWorkspace = filepath.Clean(workspace)
			canonicalWorkspace, workspaceWitness, workspaceIdentity, workspaceErr = inspectGrantPath(logicalWorkspace, PathTypeDirectory, PathAccessReadOnly)
		}
		if workspaceErr != nil || logicalWorkspace != grant.workspaceLogicalPath || canonicalWorkspace != grant.workspacePath || workspaceIdentity != grant.workspaceIdentity || !equalPathWitness(workspaceWitness, grant.workspaceLogicalWitness) {
			return nil, errors.New("workspace identity changed")
		}
	}
	for _, grant := range result {
		canonical, logicalWitness, identity, err := inspectGrantPath(grant.logicalPath, grant.Type, grant.Access)
		if err != nil || canonical != grant.path || identity != grant.identity || !equalPathWitness(logicalWitness, grant.logicalWitness) {
			return nil, errors.New("selected path identity changed")
		}
		if pathsOverlap(canonical, sessions) || pathsOverlap(canonical, SessionOperationsDirectory(sessions)) {
			return nil, errors.New("path overlaps protected private state")
		}
	}
	return result, nil
}

func equalPathWitness(left, right []pathIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func reduceFilesystemGrants(grants []FilesystemGrant, workspace string, workspaceAccess WorkspaceAccess) []FilesystemGrant {
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].path != grants[j].path {
			return grants[i].path < grants[j].path
		}
		return grants[i].Access > grants[j].Access
	})
	result := make([]FilesystemGrant, 0, len(grants))
	for _, grant := range grants {
		if withinOrEqual(workspace, grant.path) && (grant.Access == PathAccessReadOnly || workspaceWritable(workspaceAccess)) {
			grant.effective = false
			result = append(result, grant)
			continue
		}
		dominated := false
		for _, current := range result {
			if current.effective && withinOrEqual(current.path, grant.path) && (current.Access == PathAccessReadWrite || grant.Access == PathAccessReadOnly) {
				dominated = true
				break
			}
		}
		grant.effective = !dominated
		result = append(result, grant)
	}
	return result
}

func withinOrEqual(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

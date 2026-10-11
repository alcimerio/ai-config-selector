package launch

import (
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// This is an internal, pure compiler, not a launcher. It consumes the filesystem
// facet of resolved Profile/recipe authority and a captured canonical tree. No
// filesystem access, default macOS runtime paths, feature probes or execution
// occur here. Production Linux admission remains closed.
//
// A future launcher must capture complete directory listings without following
// links, revalidate/pin source identities, build the private view, and install
// all the required restrictions before untrusted execution. A plan is not proof
// that any of these operations succeeded.
type linuxFilesystemSnapshot map[string]linuxFilesystemNode

type linuxFilesystemNode struct {
	identity       pathIdentity
	mountID        uint64 // Captured mount ID, including same-device bind boundaries.
	filesystemType int64
	children       []string // Complete immediate basenames, only for directories.
}

type linuxUnixSocketPolicy uint8

const (
	linuxUnixSocketsUnmediated linuxUnixSocketPolicy = iota
	// ABI 6 does not mediate pathname socket connections. This policy obligates
	// the sealed launcher to deny socket(AF_UNIX), deny io_uring socket creation,
	// and exclude inherited/received host socket FDs. It permits private
	// socketpair IPC. A scan alone cannot prevent post-scan socket insertion.
	linuxUnixSocketsDenyCreation
)

type linuxFilesystemFeatures struct {
	landlockABI int
	unixSockets linuxUnixSocketPolicy
}

type linuxMountKind uint8

const (
	linuxMountDirectory        linuxMountKind = iota // Synthetic directory in private root.
	linuxMountReadOnly                               // bwrap --ro-bind, recursively read-only.
	linuxMountReadWrite                              // bwrap --bind.
	linuxMountSealRoot                               // bwrap --remount-ro /, after setup.
	linuxMountRuntimeAlias                           // Exact RO ELF/terminfo alias, no host symlink.
	linuxMountEmptyCodexConfig                       // Sealed, generated empty MCP selection in Session HOME.
)

type linuxMount struct {
	kind        linuxMountKind
	source      string
	destination string
	identity    pathIdentity // Source witness; never a substitute for a pinned FD.
	mountID     uint64
}

type linuxLandlockRule struct {
	path   string // Resolved in the completed private mount view, not on the host.
	access uint64
}

type linuxFilesystemPlan struct {
	mounts         []linuxMount
	rules          []linuxLandlockRule
	handledAccess  uint64
	scoped         uint64
	ancestorGuards []string
	unixSockets    linuxUnixSocketPolicy
}

const (
	linuxReadFile  = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE
	linuxReadTree  = linuxReadFile | unix.LANDLOCK_ACCESS_FS_READ_DIR
	linuxWriteFile = unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	linuxWriteTree = linuxWriteFile | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER
	// Never shrink this mask to what a host happens to support. Device creation
	// and device ioctls are handled but receive no authority from this compiler.
	linuxHandledFilesystem = linuxReadTree | linuxWriteTree | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

type linuxPathAuthority struct {
	path     string
	access   PathAccess
	kind     PathType
	required bool // Runtime inputs must not be partially removed by exclusions.
	session  bool
}

// This prospective runtime is explicit and remains outside production runtime
// selection. In particular the shipped macOS authority must never be accepted
// as an instruction to expose Linux system directories or desktop services.
func linuxFilesystemRuntimeAuthority() RuntimeAuthority {
	value := DefaultRuntimeAuthority()
	value.SystemReadMode = "explicit-linux-runtime-inputs"
	value.NetworkMode = "outbound-ip-no-listen-unix-sockets-denied"
	value.SysctlNames = nil
	value.MachServices = nil
	return value
}

// compileLinuxFilesystemPlan deliberately rejects requests it cannot represent
// faithfully. In particular, mounts/Landlock cannot subtract an absent name
// while retaining arbitrary creation in its writable parent. Freezing that
// parent would silently change a read-write grant, so it is an error instead.
// privatePaths names credential stores and supervisor state, not projections.
func compileLinuxFilesystemPlan(request validatedProcessRequest, snapshot linuxFilesystemSnapshot, features linuxFilesystemFeatures, privatePaths []string) (linuxFilesystemPlan, error) {
	fail := func(reason string) (linuxFilesystemPlan, error) {
		return linuxFilesystemPlan{}, errors.New("Linux filesystem plan rejected: " + reason)
	}
	if features.landlockABI < 6 {
		return fail("Landlock ABI 6 or later is required")
	}
	if features.unixSockets != linuxUnixSocketsDenyCreation {
		return fail("sealed Unix socket denial is required for live directory grants")
	}
	if !reflect.DeepEqual(request.runtimeAuthority, linuxFilesystemRuntimeAuthority()) {
		return fail("explicit Linux runtime authority is required")
	}
	if request.reserveMCPConfigNames || request.selectedMCPConfig != "" {
		return fail("global MCP basename denials are not representable")
	}
	if len(request.runtimeProbeTraversalPaths) != 0 {
		return fail("runtime symlink traversal is not representable")
	}
	for _, path := range []string{request.workspace, request.sessionsDirectory, request.sessionDirectory, request.sessionHome, request.temporaryDirectory, request.executable} {
		if !linuxCanonicalPlanPath(path) {
			return fail("noncanonical required path")
		}
	}
	if !pathWithin(request.sessionsDirectory, request.sessionDirectory) || !pathWithin(request.sessionDirectory, request.sessionHome) ||
		!pathWithin(request.sessionDirectory, request.temporaryDirectory) || pathsOverlap(request.sessionHome, request.temporaryDirectory) {
		return fail("invalid Session layout")
	}
	access, err := normalizeWorkspaceAccess(request.workspaceAccess)
	if err != nil {
		return fail("invalid workspace access")
	}
	workspaceAccess := PathAccessReadOnly
	if access == WorkspaceAccessReadWrite {
		workspaceAccess = PathAccessReadWrite
	}
	authority := []linuxPathAuthority{
		{path: request.workspace, access: workspaceAccess, kind: PathTypeDirectory},
		{path: request.sessionHome, access: PathAccessReadWrite, kind: PathTypeDirectory, session: true},
		{path: request.temporaryDirectory, access: PathAccessReadWrite, kind: PathTypeDirectory, session: true},
		{path: request.executable, access: PathAccessReadOnly, kind: PathTypeFile, required: true},
	}
	for _, grant := range request.filesystemGrants {
		if grant.logicalPath != grant.path || snapshot[grant.path].identity != grant.identity {
			return fail("aliased or changed path grant")
		}
		if grant.effective {
			authority = append(authority, linuxPathAuthority{path: grant.path, access: grant.Access, kind: grant.Type})
		}
	}
	for _, grant := range request.executableGrants {
		if grant.logicalPath != grant.path || snapshot[grant.path].identity != grant.identity {
			return fail("aliased or changed executable grant")
		}
		authority = append(authority, linuxPathAuthority{path: grant.path, access: PathAccessReadOnly, kind: PathTypeFile, required: true})
	}
	for _, path := range request.runtimeInputs {
		kind := PathTypeFile
		if snapshot[path].identity.mode.IsDir() {
			kind = PathTypeDirectory
		}
		authority = append(authority, linuxPathAuthority{path: path, access: PathAccessReadOnly, kind: kind, required: true})
	}
	for _, path := range request.runtimeProbePaths {
		if !linuxCanonicalPlanPath(path) {
			return fail("noncanonical runtime probe")
		}
		if _, exists := snapshot[path]; exists {
			authority = append(authority, linuxPathAuthority{path: path, access: PathAccessReadOnly, kind: PathTypeFile, required: true})
		}
	}
	private := append([]string{request.sessionsDirectory, SessionOperationsDirectory(request.sessionsDirectory)}, privatePaths...)
	for _, path := range private {
		if !linuxCanonicalPlanPath(path) {
			return fail("noncanonical private path")
		}
	}
	var denied []string
	guards := map[string]bool{}
	guardAncestors := func(path string) {
		for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
			guards[parent] = true
			if parent == "/" {
				break
			}
		}
	}
	for _, exclusion := range request.filesystemExclusions {
		if !linuxCanonicalPlanPath(exclusion.path) || exclusion.logicalPath != exclusion.path ||
			snapshot[exclusion.witness.path].identity != exclusion.witness.identity || exclusion.witness.identity.inode == 0 {
			return fail("aliased or changed exclusion")
		}
		_, exists := snapshot[exclusion.path]
		if exclusion.exists != exists {
			return fail("exclusion existence changed")
		}
		if exists && exclusion.witness.path != exclusion.path {
			return fail("invalid existing exclusion witness")
		}
		if !exists {
			if !linuxCanonicalPlanPath(exclusion.firstMissing) || !withinOrEqual(exclusion.firstMissing, exclusion.path) ||
				filepath.Dir(exclusion.firstMissing) != exclusion.witness.path || !exclusion.witness.identity.mode.IsDir() {
				return fail("invalid absent exclusion witness")
			}
			if _, exists := snapshot[exclusion.firstMissing]; exists {
				return fail("absent exclusion ancestor changed")
			}
		}
		denied = append(denied, exclusion.path)
		guardAncestors(exclusion.path)
	}
	var protected []string
	for _, protection := range request.sessionProtections {
		node, exists := snapshot[protection.path]
		if !linuxCanonicalPlanPath(protection.path) || !pathWithin(request.sessionHome, protection.path) || !exists || node.identity != protection.identity ||
			(node.identity.mode.IsDir() && !protection.recursive) {
			return fail("invalid or nonrecursive directory protection")
		}
		protected = append(protected, protection.path)
		guardAncestors(protection.path)
	}
	for _, grant := range authority {
		if !linuxCanonicalPlanPath(grant.path) || filepath.Dir(grant.path) == "/" || linuxReservedHostTree(grant.path) ||
			(grant.access != PathAccessReadOnly && grant.access != PathAccessReadWrite) ||
			(grant.kind != PathTypeFile && grant.kind != PathTypeDirectory) {
			return fail("invalid or overly broad authority")
		}
		node, exists := snapshot[grant.path]
		if !exists || (grant.kind == PathTypeDirectory) != node.identity.mode.IsDir() {
			return fail("missing or changed authority source")
		}
		for index, path := range private {
			if grant.session && index == 0 {
				continue // Only the selected HOME/tmp projections cross this boundary.
			}
			if pathsOverlap(path, grant.path) {
				return fail("authority overlaps private state")
			}
		}
		for _, path := range denied {
			if withinOrEqual(path, grant.path) || (grant.required && pathsOverlap(path, grant.path)) {
				return fail("exclusion conflicts with required authority")
			}
		}
		for _, path := range append(append([]string(nil), denied...), protected...) {
			if grant.access == PathAccessReadWrite && pathsOverlap(path, grant.path) {
				return fail("writable authority overlaps an exclusion or protection")
			}
		}
		if grant.required {
			for _, other := range authority {
				if other.access == PathAccessReadWrite && pathsOverlap(other.path, grant.path) {
					return fail("writable authority overlaps a runtime input")
				}
			}
		}
	}

	plan := linuxFilesystemPlan{handledAccess: linuxHandledFilesystem,
		scoped: unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL, unixSockets: features.unixSockets}
	mounts := map[string]linuxMount{"/": {kind: linuxMountDirectory, destination: "/"}}
	rules := map[string]uint64{}
	// Reject links and special files even in read-only trees. A recursive bind
	// must not import sockets, nested special files, or aliases to denied data.
	// The trusted capture must also reject nested mounts and supply a complete
	// listing. Bounds keep malformed snapshots from causing unbounded recursion.
	visited := map[string]bool{}
	var validateTree func(string, int) error
	validateTree = func(path string, depth int) error {
		for _, exclusion := range denied {
			if withinOrEqual(exclusion, path) {
				return nil
			}
		}
		if visited[path] {
			return nil
		}
		if depth > 256 || len(visited) >= 65536 {
			return errors.New("tree exceeds compiler limits")
		}
		visited[path] = true
		node, exists := snapshot[path]
		if !exists || node.identity.inode == 0 || (!node.identity.mode.IsRegular() && !node.identity.mode.IsDir()) ||
			node.mountID == 0 || (node.identity.mode.IsRegular() && (node.identity.links != 1 || len(node.children) != 0)) {
			return errors.New("incomplete tree, link, socket or special file")
		}
		if !linuxDataFilesystem(node.filesystemType) {
			return errors.New("unknown or kernel interface filesystem")
		}
		for _, exclusion := range denied {
			if pathWithin(path, exclusion) && !node.identity.mode.IsDir() {
				return errors.New("exclusion traverses a non-directory")
			}
		}
		seen := map[string]bool{}
		for _, child := range node.children {
			if child == "." || child == ".." || child == "" || strings.ContainsAny(child, "/\x00") || seen[child] {
				return errors.New("invalid directory listing")
			}
			seen[child] = true
			childPath := filepath.Join(path, child)
			if childNode, exists := snapshot[childPath]; !exists || childNode.mountID != node.mountID ||
				childNode.identity.device != node.identity.device || childNode.filesystemType != node.filesystemType {
				return errors.New("incomplete tree or nested mount")
			}
			if err := validateTree(childPath, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, grant := range authority {
		if err := validateTree(grant.path, 0); err != nil {
			return fail(err.Error())
		}
	}
	var emit func(linuxPathAuthority)
	emit = func(grant linuxPathAuthority) {
		for _, other := range authority {
			if other.access == PathAccessReadWrite && withinOrEqual(other.path, grant.path) {
				grant.access = PathAccessReadWrite // RO grants never subtract authority.
			}
		}
		for _, exclusion := range denied {
			if withinOrEqual(exclusion, grant.path) {
				return
			}
		}
		for _, exclusion := range denied {
			if pathWithin(grant.path, exclusion) {
				// Rebuild this read-only directory in the private root. Do not
				// bind an ancestor of a denial or create a host placeholder.
				mounts[grant.path] = linuxMount{kind: linuxMountDirectory, destination: grant.path}
				rules[grant.path] |= unix.LANDLOCK_ACCESS_FS_READ_DIR
				for _, child := range snapshot[grant.path].children {
					path := filepath.Join(grant.path, child)
					kind := PathTypeFile
					if snapshot[path].identity.mode.IsDir() {
						kind = PathTypeDirectory
					}
					emit(linuxPathAuthority{path: path, access: grant.access, kind: kind})
				}
				return
			}
		}
		kind, rights := linuxMountReadOnly, uint64(linuxReadFile)
		if grant.kind == PathTypeDirectory {
			rights = linuxReadTree
		}
		if grant.access == PathAccessReadWrite {
			kind = linuxMountReadWrite
			rights |= linuxWriteFile
			if grant.kind == PathTypeDirectory {
				rights |= linuxWriteTree
			}
		}
		if previous, exists := mounts[grant.path]; exists && previous.kind == linuxMountReadWrite {
			kind = linuxMountReadWrite // Profile grants compose by union.
		}
		mounts[grant.path] = linuxMount{kind: kind, source: grant.path, destination: grant.path,
			identity: snapshot[grant.path].identity, mountID: snapshot[grant.path].mountID}
		rules[grant.path] |= rights
	}
	for _, grant := range authority {
		emit(grant)
	}
	for path := range mounts {
		for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
			if _, exists := mounts[parent]; !exists {
				mounts[parent] = linuxMount{kind: linuxMountDirectory, destination: parent}
			}
		}
	}
	for _, mount := range mounts {
		plan.mounts = append(plan.mounts, mount)
	}
	// Parents before children; path order also makes equivalent inputs stable.
	sort.Slice(plan.mounts, func(i, j int) bool {
		return plan.mounts[i].destination < plan.mounts[j].destination
	})
	plan.mounts = append(plan.mounts, linuxMount{kind: linuxMountSealRoot, destination: "/"})
	for path, access := range rules {
		plan.rules = append(plan.rules, linuxLandlockRule{path: path, access: access})
	}
	sort.Slice(plan.rules, func(i, j int) bool { return plan.rules[i].path < plan.rules[j].path })
	for path := range guards {
		plan.ancestorGuards = append(plan.ancestorGuards, path)
	}
	sort.Strings(plan.ancestorGuards)
	return plan, nil
}

func linuxCanonicalPlanPath(path string) bool {
	return filepath.IsAbs(path) && path != "/" && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func linuxReservedHostTree(path string) bool {
	for _, root := range []string{"/proc", "/sys", "/dev", "/run"} {
		if withinOrEqual(root, path) {
			return true
		}
	}
	return false
}

func linuxDataFilesystem(kind int64) bool {
	switch kind {
	case 0, unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC, unix.CGROUP_SUPER_MAGIC, unix.CGROUP2_SUPER_MAGIC,
		unix.DEVPTS_SUPER_MAGIC, unix.DEBUGFS_MAGIC, unix.TRACEFS_MAGIC, unix.SECURITYFS_MAGIC, unix.BPF_FS_MAGIC:
		return false
	}
	return true
}

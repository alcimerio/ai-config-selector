package launch

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These fixtures are complete, synthetic captures. They prove compilation, not
// mount or Landlock enforcement, and need no native kernel prerequisites.
type linuxPlanFixture struct {
	request  validatedProcessRequest
	tree     linuxFilesystemSnapshot
	features linuxFilesystemFeatures
}

func newLinuxPlanFixture() linuxPlanFixture {
	f := linuxPlanFixture{
		request: validatedProcessRequest{
			workspace: "/work/project", workspaceAccess: WorkspaceAccessReadOnly,
			sessionsDirectory: "/state/acs/sessions", sessionDirectory: "/state/acs/sessions/one",
			sessionHome: "/state/acs/sessions/one/home", temporaryDirectory: "/state/acs/sessions/one/tmp",
			executable: "/usr/bin/target", runtimeAuthority: linuxFilesystemRuntimeAuthority(),
		},
		tree:     linuxFilesystemSnapshot{},
		features: linuxFilesystemFeatures{landlockABI: 6, unixSockets: linuxUnixSocketsDenyCreation},
	}
	f.directory(f.request.workspace)
	f.directory(f.request.sessionHome)
	f.directory(f.request.temporaryDirectory)
	f.file(f.request.executable)
	return f
}

func (f *linuxPlanFixture) node(path string, mode os.FileMode) {
	f.tree[path] = linuxFilesystemNode{identity: pathIdentity{device: 1, inode: uint64(len(f.tree) + 1), mode: mode, links: 1}, mountID: 1, filesystemType: unix.EXT4_SUPER_MAGIC}
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		parent := path[:i]
		if node, exists := f.tree[parent]; exists {
			node.children = append(node.children, path[i+1:])
			f.tree[parent] = node
		}
	}
}

func (f *linuxPlanFixture) directory(path string) { f.node(path, os.ModeDir|0o700) }
func (f *linuxPlanFixture) file(path string)      { f.node(path, 0o600) }

func (f *linuxPlanFixture) grant(path string, access PathAccess) {
	kind := PathTypeFile
	if f.tree[path].identity.mode.IsDir() {
		kind = PathTypeDirectory
	}
	f.request.filesystemGrants = append(f.request.filesystemGrants, FilesystemGrant{
		ID: "fixture", path: path, logicalPath: path, identity: f.tree[path].identity, Access: access, Type: kind, effective: true,
	})
}

func (f *linuxPlanFixture) exclude(path, captured, firstMissing string) {
	f.request.filesystemExclusions = append(f.request.filesystemExclusions, FilesystemExclusion{
		ID: "excluded", path: path, logicalPath: path, exists: firstMissing == "", firstMissing: firstMissing,
		witness: FilesystemGrant{path: captured, identity: f.tree[captured].identity},
	})
}

func (f *linuxPlanFixture) compile(t *testing.T) linuxFilesystemPlan {
	t.Helper()
	plan, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func planMount(t *testing.T, plan linuxFilesystemPlan, path string) linuxMount {
	t.Helper()
	for _, mount := range plan.mounts {
		if mount.destination == path && mount.kind != linuxMountSealRoot {
			return mount
		}
	}
	t.Fatalf("missing mount at %s", path)
	return linuxMount{}
}

func planRights(plan linuxFilesystemPlan, path string) uint64 {
	var result uint64
	for _, rule := range plan.rules {
		if withinOrEqual(rule.path, path) {
			result |= rule.access
		}
	}
	return result
}

func TestLinuxFilesystemPlanReadWriteAndRuntime(t *testing.T) {
	f := newLinuxPlanFixture()
	f.file("/work/project/readme")
	f.directory("/work/project/output")
	f.grant("/work/project/output", PathAccessReadWrite)
	f.file("/work/project/notes")
	f.grant("/work/project/notes", PathAccessReadWrite)
	f.file("/etc/ssl/ca-bundle")
	f.directory("/usr/lib/runtime")
	f.file("/usr/lib/runtime/loader")
	f.request.runtimeInputs = []string{"/etc/ssl/ca-bundle", "/usr/lib/runtime"}
	f.request.runtimeProbePaths = []string{"/etc/resolver/missing", "/etc/ssl/ca-bundle"}
	f.file("/tools/bin/mcp")
	f.request.executableGrants = []ExecutableGrant{{path: "/tools/bin/mcp", logicalPath: "/tools/bin/mcp", identity: f.tree["/tools/bin/mcp"].identity}}
	plan := f.compile(t)
	for path, want := range map[string]linuxMountKind{
		"/work/project": linuxMountReadOnly, "/work/project/output": linuxMountReadWrite,
		"/work/project/notes": linuxMountReadWrite, f.request.sessionHome: linuxMountReadWrite,
		f.request.temporaryDirectory: linuxMountReadWrite, f.request.executable: linuxMountReadOnly,
		"/etc/ssl/ca-bundle": linuxMountReadOnly, "/usr/lib/runtime": linuxMountReadOnly, "/tools/bin/mcp": linuxMountReadOnly,
	} {
		if got := planMount(t, plan, path); got.kind != want || got.identity != f.tree[path].identity || got.mountID != f.tree[path].mountID {
			t.Errorf("mount %s = %+v, want kind %v and captured identity", path, got, want)
		}
	}
	for _, path := range []string{"/work/project/output/new", f.request.sessionHome + "/config", f.request.temporaryDirectory + "/new"} {
		if got := planRights(plan, path); got&linuxWriteTree != linuxWriteTree {
			t.Errorf("missing directory write rights for %s: %#x", path, got)
		}
	}
	for _, path := range []string{"/work/project/readme", "/usr/lib/runtime/loader", "/etc/ssl/ca-bundle", "/tools/bin/mcp"} {
		if got := planRights(plan, path); got&linuxReadFile != linuxReadFile || got&linuxWriteTree != 0 {
			t.Errorf("read-only rights for %s = %#x", path, got)
		}
	}
	if got := planRights(plan, "/work/project/notes"); got != linuxReadTree|linuxWriteFile {
		t.Errorf("writable file rights = %#x", got)
	}
	if plan.handledAccess != 0xffff || plan.scoped != 3 || plan.unixSockets != linuxUnixSocketsDenyCreation {
		t.Errorf("incomplete mandatory restrictions: %+v", plan)
	}
	if got := plan.mounts[len(plan.mounts)-1]; got.kind != linuxMountSealRoot || got.destination != "/" {
		t.Errorf("private root must be sealed after setup: %+v", got)
	}
	for _, mount := range plan.mounts {
		if slices.Contains([]string{"/usr", "/home", "/run", "/proc", "/sys", "/etc/resolver/missing"}, mount.source) && mount.source != "" {
			t.Errorf("unexpected host exposure: %+v", mount)
		}
	}
	if got := planRights(plan, "/unselected/private"); got != 0 {
		t.Fatalf("unexpected default authority: %#x", got)
	}
}

func TestLinuxFilesystemPlanReconstructsExclusionsWithoutPlaceholders(t *testing.T) {
	f := newLinuxPlanFixture()
	f.file("/work/project/visible")
	f.file("/work/project/secret")
	f.directory("/work/project/nested")
	f.file("/work/project/nested/visible")
	f.directory("/work/project/hidden")
	f.file("/work/project/hidden/secret")
	f.directory("/work/project/output")
	f.grant("/work/project/output", PathAccessReadWrite)
	f.exclude("/work/project/secret", "/work/project/secret", "")
	f.exclude("/work/project/hidden", "/work/project/hidden", "")
	f.exclude("/work/project/nested/missing/deep/secret", "/work/project/nested", "/work/project/nested/missing")
	plan := f.compile(t)
	for _, path := range []string{"/work/project", "/work/project/nested"} {
		if mount := planMount(t, plan, path); mount.kind != linuxMountDirectory || mount.source != "" {
			t.Errorf("denial ancestor must be synthetic: %+v", mount)
		}
		if rights := planRights(plan, path); rights != unix.LANDLOCK_ACCESS_FS_READ_DIR {
			t.Errorf("denial ancestor recursively grants file access: %#x", rights)
		}
	}
	for _, path := range []string{"/work/project/visible", "/work/project/nested/visible"} {
		if mount := planMount(t, plan, path); mount.kind != linuxMountReadOnly {
			t.Errorf("allowed sibling lost: %+v", mount)
		}
	}
	if mount := planMount(t, plan, "/work/project/output"); mount.kind != linuxMountReadWrite {
		t.Errorf("disjoint writable subtree lost: %+v", mount)
	}
	for _, exclusion := range f.request.filesystemExclusions {
		for _, mount := range plan.mounts {
			if mount.source != "" && pathsOverlap(mount.source, exclusion.path) {
				t.Errorf("excluded host data is reachable through %+v", mount)
			}
			if withinOrEqual(exclusion.path, mount.destination) || (exclusion.firstMissing != "" && withinOrEqual(exclusion.firstMissing, mount.destination)) {
				t.Errorf("excluded or absent name was materialized: %+v", mount)
			}
		}
	}
	for _, path := range []string{"/", "/work", "/work/project", "/work/project/nested", "/work/project/nested/missing", "/work/project/nested/missing/deep"} {
		if !slices.Contains(plan.ancestorGuards, path) {
			t.Errorf("missing ancestor guard %s", path)
		}
	}
}

func TestLinuxFilesystemPlanRejectsUnenforceableAuthority(t *testing.T) {
	tests := []struct {
		name   string
		change func(*linuxPlanFixture)
		want   string
	}{
		{"old ABI", func(f *linuxPlanFixture) { f.features.landlockABI = 5 }, "ABI 6"},
		{"socket scan is insufficient", func(f *linuxPlanFixture) { f.features.unixSockets = linuxUnixSocketsUnmediated }, "Unix socket denial"},
		{"macOS runtime", func(f *linuxPlanFixture) { f.request.runtimeAuthority = DefaultRuntimeAuthority() }, "Linux runtime authority"},
		{"implicit runtime", func(f *linuxPlanFixture) { f.request.runtimeAuthority = RuntimeAuthority{} }, "Linux runtime authority"},
		{"unknown runtime", func(f *linuxPlanFixture) { f.request.runtimeAuthority.Version++ }, "Linux runtime authority"},
		{"MCP basename reserve", func(f *linuxPlanFixture) { f.request.reserveMCPConfigNames = true }, "MCP basename"},
		{"selected MCP config", func(f *linuxPlanFixture) { f.request.selectedMCPConfig = f.request.sessionHome + "/mcp_config.json" }, "MCP basename"},
		{"runtime alias traversal", func(f *linuxPlanFixture) { f.request.runtimeProbeTraversalPaths = []string{"/etc/alias"} }, "symlink traversal"},
		{"relative workspace", func(f *linuxPlanFixture) { f.request.workspace = "relative" }, "noncanonical"},
		{"unclean workspace", func(f *linuxPlanFixture) { f.request.workspace = "/work/../project" }, "noncanonical"},
		{"NUL", func(f *linuxPlanFixture) { f.request.workspace += "\x00" }, "noncanonical"},
		{"overlapping Session paths", func(f *linuxPlanFixture) { f.request.temporaryDirectory = f.request.sessionHome + "/tmp" }, "Session layout"},
		{"broad workspace", func(f *linuxPlanFixture) { f.directory("/home"); f.request.workspace = "/home" }, "overly broad"},
		{"missing workspace", func(f *linuxPlanFixture) { delete(f.tree, f.request.workspace) }, "authority source"},
		{"host proc", func(f *linuxPlanFixture) {
			f.file("/proc/123/status")
			f.request.runtimeInputs = []string{"/proc/123/status"}
		}, "overly broad"},
		{"host cgroup", func(f *linuxPlanFixture) {
			f.directory("/sys/fs/cgroup/delegated")
			f.grant("/sys/fs/cgroup/delegated", PathAccessReadWrite)
		}, "overly broad"},
		{"wrong workspace type", func(f *linuxPlanFixture) {
			n := f.tree[f.request.workspace]
			n.identity.mode = 0o600
			f.tree[f.request.workspace] = n
		}, "authority source"},
		{"absent exclusion in RW tree", func(f *linuxPlanFixture) {
			f.request.workspaceAccess = WorkspaceAccessReadWrite
			f.exclude("/work/project/missing/deep", "/work/project", "/work/project/missing")
		}, "writable authority overlaps"},
		{"existing exclusion in RW tree", func(f *linuxPlanFixture) {
			f.request.workspaceAccess = WorkspaceAccessReadWrite
			f.file("/work/project/secret")
			f.exclude("/work/project/secret", "/work/project/secret", "")
		}, "writable authority overlaps"},
		{"RW ancestor of exclusion", func(f *linuxPlanFixture) {
			f.directory("/work/project/sub")
			f.grant("/work/project/sub", PathAccessReadWrite)
			f.exclude("/work/project/sub/missing", "/work/project/sub", "/work/project/sub/missing")
		}, "writable authority overlaps"},
		{"grant inside exclusion", func(f *linuxPlanFixture) {
			f.directory("/work/project/sub")
			f.file("/work/project/sub/data")
			f.grant("/work/project/sub/data", PathAccessReadOnly)
			f.exclude("/work/project/sub", "/work/project/sub", "")
		}, "conflicts with required authority"},
		{"excluded runtime", func(f *linuxPlanFixture) {
			f.directory("/tools/runtime")
			f.file("/tools/runtime/secret")
			f.request.runtimeInputs = []string{"/tools/runtime"}
			f.exclude("/tools/runtime/secret", "/tools/runtime/secret", "")
		}, "conflicts with required authority"},
		{"writable runtime", func(f *linuxPlanFixture) {
			f.file("/work/project/loader")
			f.request.runtimeInputs = []string{"/work/project/loader"}
			f.request.workspaceAccess = WorkspaceAccessReadWrite
		}, "writable authority overlaps a runtime"},
		{"protected MCP recipe", func(f *linuxPlanFixture) {
			path := f.request.sessionHome + "/recipes.json"
			f.file(path)
			f.request.sessionProtections = []validatedSessionProtection{{path: path, identity: f.tree[path].identity}}
		}, "writable authority overlaps"},
		{"protected auth subtree", func(f *linuxPlanFixture) {
			path := f.request.sessionHome + "/auth"
			f.directory(path)
			f.request.sessionProtections = []validatedSessionProtection{{path: path, identity: f.tree[path].identity, recursive: true}}
		}, "writable authority overlaps"},
		{"nonrecursive protection", func(f *linuxPlanFixture) {
			path := f.request.sessionHome + "/auth"
			f.directory(path)
			f.request.sessionProtections = []validatedSessionProtection{{path: path, identity: f.tree[path].identity}}
		}, "nonrecursive"},
		{"Session grant alias", func(f *linuxPlanFixture) { f.grant(f.request.sessionHome, PathAccessReadOnly) }, "overlaps private state"},
		{"supervisor state", func(f *linuxPlanFixture) {
			f.directory("/state/acs/session-operations-v1")
			f.grant("/state/acs/session-operations-v1", PathAccessReadOnly)
		}, "overlaps private state"},
		{"aliased grant", func(f *linuxPlanFixture) {
			f.file("/work/project/data")
			f.grant("/work/project/data", PathAccessReadOnly)
			f.request.filesystemGrants[0].logicalPath = "/work/alias"
		}, "aliased or changed path"},
		{"aliased exclusion", func(f *linuxPlanFixture) {
			f.exclude("/work/project/missing", "/work/project", "/work/project/missing")
			f.request.filesystemExclusions[0].logicalPath = "/work/alias"
		}, "aliased or changed exclusion"},
		{"absent ancestor changed", func(f *linuxPlanFixture) {
			f.exclude("/work/project/missing/deep", "/work/project", "/work/project/missing")
			f.directory("/work/project/missing")
		}, "absent exclusion ancestor changed"},
		{"non-directory exclusion ancestor", func(f *linuxPlanFixture) {
			f.file("/work/project/file")
			f.exclude("/work/project/file/secret", "/work/project/file", "/work/project/file/secret")
		}, "absent exclusion witness"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLinuxPlanFixture()
			tt.change(&f)
			plan, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if !reflect.DeepEqual(plan, linuxFilesystemPlan{}) {
				t.Fatal("rejected request returned a partial usable plan")
			}
			if strings.Contains(err.Error(), f.request.workspace) || strings.Contains(err.Error(), "/state/") {
				t.Fatalf("private path in diagnostic: %v", err)
			}
		})
	}
}

func TestLinuxFilesystemPlanRejectsUnsafeCapturedTrees(t *testing.T) {
	for _, kind := range []int64{0, unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC, unix.CGROUP_SUPER_MAGIC, unix.CGROUP2_SUPER_MAGIC,
		unix.DEVPTS_SUPER_MAGIC, unix.DEBUGFS_MAGIC, unix.TRACEFS_MAGIC, unix.SECURITYFS_MAGIC, unix.BPF_FS_MAGIC} {
		f := newLinuxPlanFixture()
		node := f.tree[f.request.workspace]
		node.filesystemType = kind // Also catches a kernel filesystem bind alias.
		f.tree[f.request.workspace] = node
		if _, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, nil); err == nil {
			t.Fatalf("kernel interface/unknown filesystem %#x admitted", kind)
		}
	}
	for _, mode := range []os.FileMode{os.ModeSocket, os.ModeSymlink, os.ModeNamedPipe, os.ModeDevice, os.ModeDevice | os.ModeCharDevice} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newLinuxPlanFixture()
			f.node("/work/project/unsafe", mode)
			if _, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, nil); err == nil {
				t.Fatal("special file or alias admitted")
			}
		})
	}
	for _, change := range []func(*linuxPlanFixture){
		func(f *linuxPlanFixture) {
			n := f.tree["/work/project/data"]
			n.identity.links = 2
			f.tree["/work/project/data"] = n
		},
		func(f *linuxPlanFixture) {
			n := f.tree["/work/project/data"]
			n.mountID++
			f.tree["/work/project/data"] = n
		},
		func(f *linuxPlanFixture) { delete(f.tree, "/work/project/data") },
		func(f *linuxPlanFixture) {
			n := f.tree[f.request.workspace]
			n.children = append(n.children, "../escape")
			f.tree[f.request.workspace] = n
		},
		func(f *linuxPlanFixture) {
			n := f.tree[f.request.workspace]
			n.children = append(n.children, "data")
			f.tree[f.request.workspace] = n
		},
	} {
		f := newLinuxPlanFixture()
		f.file("/work/project/data")
		change(&f)
		if _, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, nil); err == nil {
			t.Fatal("incomplete/aliased/nested-mount snapshot admitted")
		}
	}
}

func TestLinuxFilesystemPlanPrivateStoresAndDeterminism(t *testing.T) {
	f := newLinuxPlanFixture()
	f.directory("/work/project/out")
	f.grant("/work/project/out", PathAccessReadWrite)
	f.file("/work/project/out/file")
	f.grant("/work/project/out/file", PathAccessReadOnly) // Union cannot revoke RW.
	f.file("/work/project/readme")
	f.exclude("/work/project/absent", "/work/project", "/work/project/absent")
	first := f.compile(t)
	if got := planMount(t, first, "/work/project/out/file"); got.kind != linuxMountReadWrite {
		t.Fatalf("nested RO grant silently narrowed RW authority: %+v", got)
	}
	slices.Reverse(f.request.filesystemGrants)
	node := f.tree[f.request.workspace]
	slices.Reverse(node.children)
	f.tree[f.request.workspace] = node
	before := f.tree[f.request.workspace]
	before.children = slices.Clone(before.children)
	second := f.compile(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("equivalent authority produced different plans")
	}
	if !reflect.DeepEqual(before, f.tree[f.request.workspace]) {
		t.Fatal("compiler mutated input")
	}
	for _, private := range []string{"/work/project/absent/credentials", "/work/project/readme", "/work/project/out/file", f.request.sessionHome + "/provider-store"} {
		if _, err := compileLinuxFilesystemPlan(f.request, f.tree, f.features, []string{private}); err == nil {
			t.Fatalf("private store %s admitted through ancestor grant", private)
		}
	}
	f.features.landlockABI = 9
	if newer := f.compile(t); !reflect.DeepEqual(second, newer) {
		t.Fatal("newer ABI silently changed the fixed rights mask or socket policy")
	}
}

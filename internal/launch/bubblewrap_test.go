package launch

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBubblewrapRequiresCanonicalPackageExecutableMetadata(t *testing.T) {
	tests := []struct {
		name  string
		mode  os.FileMode
		owner uint32
		valid bool
	}{
		{name: "root owned package mode", mode: 0o755, owner: 0, valid: true},
		{name: "non-root owner", mode: 0o755, owner: 1000},
		{name: "owner writable only", mode: 0o700, owner: 0},
		{name: "group writable", mode: 0o775, owner: 0},
		{name: "world writable", mode: 0o757, owner: 0},
		{name: "setuid", mode: os.ModeSetuid | 0o755, owner: 0},
		{name: "symlink", mode: os.ModeSymlink | 0o755, owner: 0},
		{name: "directory", mode: os.ModeDir | 0o755, owner: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validBubblewrapExecutableMetadata(test.mode, test.owner); got != test.valid {
				t.Fatalf("metadata validity = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestBubblewrapRequiresInstalledUbuntuPackageRecord(t *testing.T) {
	for _, test := range []struct {
		name                               string
		owner, state, binary, source, arch string
		valid                              bool
	}{
		{name: "installed distribution package", owner: "bubblewrap: /usr/bin/bwrap\n", state: "ii ", binary: "bubblewrap", source: "bubblewrap", arch: "amd64", valid: true},
		{name: "unowned executable", state: "ii ", binary: "bubblewrap", source: "bubblewrap", arch: "amd64"},
		{name: "other owning package", owner: "local-bubblewrap: /usr/bin/bwrap\n", state: "ii ", binary: "bubblewrap", source: "bubblewrap", arch: "amd64"},
		{name: "removed package", owner: "bubblewrap: /usr/bin/bwrap\n", state: "rc ", binary: "bubblewrap", source: "bubblewrap", arch: "amd64"},
		{name: "other binary package", owner: "bubblewrap: /usr/bin/bwrap\n", state: "ii ", binary: "bubblewrap-custom", source: "bubblewrap", arch: "amd64"},
		{name: "other source package", owner: "bubblewrap: /usr/bin/bwrap\n", state: "ii ", binary: "bubblewrap", source: "bubblewrap-custom", arch: "amd64"},
		{name: "other architecture", owner: "bubblewrap: /usr/bin/bwrap\n", state: "ii ", binary: "bubblewrap", source: "bubblewrap", arch: "arm64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			show := strings.Join([]string{test.state, test.binary, test.source, test.arch, ""}, "\n")
			if got := validBubblewrapPackageRecord(test.owner, show, "amd64"); got != test.valid {
				t.Fatalf("package record validity = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestBubblewrapArgumentsBuildMinimalMountNamespace(t *testing.T) {
	request := validatedProcessRequest{
		workspace:          "/home/alice/project",
		sessionDirectory:   "/home/alice/.acs/sessions/session-one",
		sessionHome:        "/home/alice/.acs/sessions/session-one/home",
		temporaryDirectory: "/home/alice/.acs/sessions/session-one/tmp",
		executable:         "/opt/devin/bin/devin",
		runtimeInputs:      []string{"/etc/ssl/certs/ca-certificates.crt", "/opt/devin/runtime"},
		arguments:          []string{"skills", "list", "--json"},
		environment:        []string{"HOME=/home/alice/.acs/sessions/session-one/home", "PATH=/usr/local/bin:/usr/bin:/bin"},
	}

	arguments := bubblewrapArguments(request)
	for _, forbidden := range []string{"/home", "/run", "/var/run", "/var/run/docker.sock", "/run/user"} {
		if hasBubblewrapMount(arguments, "--ro-bind", forbidden, forbidden) {
			t.Fatalf("Bubblewrap arguments expose forbidden host path %q: %q", forbidden, arguments)
		}
	}
	for _, writable := range []string{request.workspace, request.sessionDirectory} {
		if !hasBubblewrapMount(arguments, "--bind", writable, writable) {
			t.Errorf("Bubblewrap arguments do not mount %q writable: %q", writable, arguments)
		}
	}
	for _, readonly := range append([]string{request.executable}, request.runtimeInputs...) {
		if !hasBubblewrapMount(arguments, "--ro-bind", readonly, readonly) {
			t.Errorf("Bubblewrap arguments do not mount %q read-only: %q", readonly, arguments)
		}
	}
	for _, option := range []string{"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup", "--die-with-parent", "--clearenv"} {
		if !containsArgument(arguments, option) {
			t.Errorf("Bubblewrap arguments omit %s: %q", option, arguments)
		}
	}
	if containsArgument(arguments, "--unshare-net") || containsArgument(arguments, "--share-net") {
		t.Fatalf("Bubblewrap arguments alter the host IP network namespace: %q", arguments)
	}
	if got := arguments[len(arguments)-4:]; !reflect.DeepEqual(got, []string{"--", request.executable, "skills", "list", "--json"}[1:]) {
		t.Fatalf("Bubblewrap target suffix = %q", got)
	}
	if !containsAdjacent(arguments, "--chdir", request.workspace) {
		t.Errorf("Bubblewrap arguments do not select the workspace: %q", arguments)
	}
	for _, entry := range request.environment {
		key, value, _ := splitEnvironmentEntry(entry)
		if !containsTriple(arguments, "--setenv", key, value) {
			t.Errorf("Bubblewrap arguments omit environment entry %q: %q", entry, arguments)
		}
	}
	if containsArgument(arguments, "PRIVATE_ENVIRONMENT_VALUE") {
		t.Fatalf("Bubblewrap arguments include an unexpected environment value: %q", arguments)
	}
}

func TestBubblewrapMountDestinationsCreateOnlyRequiredParents(t *testing.T) {
	paths := bubblewrapParentDirectories([]string{"/home/alice/project", "/home/alice/.acs/sessions/session-one", "/opt/devin/bin/devin"})
	want := []string{"/home", "/opt", "/home/alice", "/opt/devin", "/home/alice/.acs", "/opt/devin/bin", "/home/alice/.acs/sessions"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("mount parents = %q, want %q", paths, want)
	}
	for _, path := range paths {
		if path == filepath.Clean("/") {
			t.Fatal("mount parents include namespace root")
		}
	}
}

func hasBubblewrapMount(arguments []string, option, source, destination string) bool {
	return containsTriple(arguments, option, source, destination)
}

func containsArgument(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func containsAdjacent(arguments []string, first, second string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second {
			return true
		}
	}
	return false
}

func containsTriple(arguments []string, first, second, third string) bool {
	for index := 0; index+2 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second && arguments[index+2] == third {
			return true
		}
	}
	return false
}

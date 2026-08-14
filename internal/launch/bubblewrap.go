package launch

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const bubblewrapEnvironmentExecutable = "/usr/bin/env"

func validBubblewrapExecutableMetadata(mode os.FileMode, owner uint32) bool {
	const special = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return mode.IsRegular() && mode&special == 0 && owner == 0 && mode.Perm() == 0o755
}

func validBubblewrapPackageRecord(ownerOutput, packageOutput, architecture string) bool {
	fields := strings.Split(strings.TrimSuffix(packageOutput, "\n"), "\n")
	return strings.TrimSpace(ownerOutput) == "bubblewrap: /usr/bin/bwrap" &&
		len(fields) == 4 && fields[0] == "ii " && fields[1] == "bubblewrap" &&
		fields[2] == "bubblewrap" && fields[3] == architecture
}

var bubblewrapSystemReadOnlyPaths = []string{
	"/etc/alternatives",
	"/etc/ca-certificates",
	"/etc/ssl",
	"/etc/group",
	"/etc/hosts",
	"/etc/ld.so.cache",
	"/etc/localtime",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/resolv.conf",
}

func bubblewrapArguments(request validatedProcessRequest) []string {
	arguments := []string{
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
		"--die-with-parent",
		"--clearenv",
		"--proc", "/proc",
		"--dev", "/dev",
		"--dir", "/etc",
		"--dir", "/run",
		"--dir", "/var",
		"--dir", "/tmp",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/sbin", "/sbin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "../run", "/var/run",
		"--ro-bind", "/usr", "/usr",
	}

	for _, path := range bubblewrapSystemReadOnlyPaths {
		arguments = append(arguments, "--ro-bind-try", path, path)
	}

	mountPaths := []string{request.workspace, request.sessionDirectory, request.executable}
	mountPaths = append(mountPaths, request.runtimeInputs...)
	for _, directory := range bubblewrapParentDirectories(mountPaths) {
		arguments = append(arguments, "--dir", directory)
	}
	arguments = append(arguments,
		"--bind", request.workspace, request.workspace,
		"--bind", request.sessionDirectory, request.sessionDirectory,
		"--ro-bind", request.executable, request.executable,
	)
	for _, input := range request.runtimeInputs {
		arguments = append(arguments, "--ro-bind", input, input)
	}
	arguments = append(arguments, "--remount-ro", "/")
	for _, entry := range request.environment {
		key, value, found := splitEnvironmentEntry(entry)
		if found {
			arguments = append(arguments, "--setenv", key, value)
		}
	}
	arguments = append(arguments, "--chdir", request.workspace, "--", bubblewrapEnvironmentExecutable, "-u", "PWD", "--", request.executable)
	arguments = append(arguments, request.arguments...)
	return arguments
}

func splitEnvironmentEntry(entry string) (string, string, bool) {
	return strings.Cut(entry, "=")
}

func bubblewrapParentDirectories(paths []string) []string {
	unique := make(map[string]struct{})
	for _, path := range paths {
		for parent := filepath.Dir(filepath.Clean(path)); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
			if isBubblewrapSystemDirectory(parent) {
				break
			}
			unique[parent] = struct{}{}
		}
	}
	directories := make([]string, 0, len(unique))
	for directory := range unique {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool {
		leftDepth := strings.Count(directories[left], string(filepath.Separator))
		rightDepth := strings.Count(directories[right], string(filepath.Separator))
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[left] < directories[right]
	})
	return directories
}

func isBubblewrapSystemDirectory(path string) bool {
	switch path {
	case "/bin", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/tmp", "/usr", "/var":
		return true
	default:
		return false
	}
}

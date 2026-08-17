//go:build linux

package acceptance_test

import (
	"os/exec"
	"testing"
)

func promotedArtifactMissingBackendCommand(t *testing.T, binary, home, path, workspace string) *exec.Cmd {
	t.Helper()
	// The outer namespace intentionally masks only /usr/bin. The supplied,
	// statically built candidate can run its startup check, but its required
	// /usr/bin/bwrap is absent before any fake Devin process is eligible to run.
	arguments := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--clearenv", "--proc", "/proc", "--dev", "/dev",
		"--ro-bind", "/", "/", "--tmpfs", "/usr/bin",
		"--setenv", "HOME", home,
		"--setenv", "PATH", path,
		"--setenv", "TERM", "xterm-256color",
		"--chdir", workspace,
		"--", binary, "devin", "--profile", "reviews",
	}
	return exec.Command("/usr/bin/bwrap", arguments...)
}

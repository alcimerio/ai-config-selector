package linuxprobe

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func nativeUnavailable(t *testing.T, reason string) {
	t.Helper()
	if _, required := os.LookupEnv("ACS_LINUX_NATIVE_REQUIRED"); required {
		t.Fatalf("required native Linux prerequisite unavailable: %s", reason)
	}
	t.Skip("native Linux prerequisite unavailable: " + reason + "; set ACS_LINUX_NATIVE_REQUIRED=1 to require it")
}

func TestNativeLandlockABI(t *testing.T) {
	abi, err := landlockABI()
	if err != nil || abi < minLandlockABI {
		nativeUnavailable(t, "Landlock ABI 6+ query")
	}
	t.Logf("kernel reported Landlock ABI %d; enforcement is not tested here", abi)
}

// This records read-only observations even on an unqualified host. It never
// claims readiness: TestNativeLinuxPrerequisites must pass separately inside
// the delegated scope before the containment suites can run.
func TestNativeLinuxHostEvidence(t *testing.T) {
	release, version, err := kernelVersion()
	t.Logf("uname: release=%q version=%q arch=%s uid=%d euid=%d error=%v", release, version, runtime.GOARCH, os.Getuid(), os.Geteuid(), err)
	abi, err := landlockABI()
	t.Logf("Landlock ABI: %d (required >=6), error=%v", abi, err)
	for _, path := range []string{
		"/etc/os-release",
		"/proc/sys/kernel/unprivileged_userns_clone",
		"/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
		"/proc/sys/user/max_user_namespaces",
		"/proc/sys/user/max_mnt_namespaces",
		"/proc/sys/user/max_pid_namespaces",
		"/sys/module/apparmor/parameters/enabled",
		"/sys/kernel/security/lsm",
		"/proc/self/attr/current",
		"/proc/self/cgroup",
	} {
		data, err := readSmallFile(path)
		t.Logf("%s: %q error=%v", path, strings.TrimSpace(string(data)), err)
	}
	data, err := readSmallFile("/proc/self/cgroup")
	if relative, ok := unifiedCgroupPath(data); err == nil && ok {
		base := "/sys/fs/cgroup/" + relative
		for _, name := range []string{"", "/cgroup.procs", "/cgroup.kill"} {
			var stat unix.Stat_t
			err := unix.Lstat(base+name, &stat)
			t.Logf("cgroup ownership %s: uid=%d gid=%d mode=%#o error=%v", name, stat.Uid, stat.Gid, stat.Mode, err)
		}
		for _, name := range []string{"cgroup.type", "cgroup.controllers", "cgroup.subtree_control", "cgroup.events"} {
			data, err := readSmallFile(base + "/" + name)
			t.Logf("%s: %q error=%v", name, strings.TrimSpace(string(data)), err)
		}
	}
	parent, err := OpenDelegatedCgroup()
	if parent != nil {
		_ = parent.Close()
	}
	t.Logf("owned cgroup v2 delegation open: %v (placement, kill and empty proof tested separately)", err)
}

func TestNativeUserNamespaces(t *testing.T) {
	if probeUserNamespaces(context.Background()) != nil {
		nativeUnavailable(t, "unprivileged user/mount/PID namespace creation and private mount operation")
	}
}

func TestNativeSeccomp(t *testing.T) {
	if probeSeccomp(context.Background()) != nil {
		nativeUnavailable(t, "seccomp filter installation and positive/negative syscall controls")
	}
	// Installing the helper's filter must not have confined the test process.
	if _, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0); errno != 0 {
		t.Fatal("seccomp escaped helper")
	}
}

func TestNativeCgroupDelegation(t *testing.T) {
	if err := probeCgroup(context.Background()); err != nil {
		if err == errCgroupCleanup {
			t.Fatal("probe cgroup cleanup is unproven")
		}
		nativeUnavailable(t, "owned cgroup v2 delegation with helper placement, cgroup.kill, empty proof and removal")
	}
}

func TestNativeSystemBwrapIdentity(t *testing.T) {
	id, err := inspectBwrap()
	if err != nil {
		nativeUnavailable(t, "trusted root-owned /usr/bin/bwrap and parent directories, without user write access")
	}
	if len(id.SHA256) != 64 {
		t.Fatal("missing executable identity")
	}
}

func TestNativeLinuxPrerequisites(t *testing.T) {
	r := Probe(context.Background())
	for _, c := range r.Checks {
		t.Logf("%s: %s (%s): %s", c.ID, c.Status, c.Code, c.NextStep)
	}
	if !r.PrerequisitesPassed() {
		nativeUnavailable(t, "complete Ubuntu 24.04 amd64 host prerequisites")
	}
}

func TestNativeRequiredModeRejectsSkipping(t *testing.T) {
	for _, required := range []bool{false, true} {
		cmd := exec.Command("/proc/self/exe", "-test.run=^TestNativeUnavailableFixture$", "-test.v")
		cmd.Env = []string{"ACS_LINUX_PROBE_SKIP_TEST=1"}
		if required {
			cmd.Env = append(cmd.Env, "ACS_LINUX_NATIVE_REQUIRED=1")
		}
		output, err := cmd.CombinedOutput()
		if required {
			if err == nil || !bytes.Contains(output, []byte("--- FAIL:")) || bytes.Contains(output, []byte("--- SKIP:")) {
				t.Fatalf("required prerequisite did not fail: %s", output)
			}
		} else if err != nil || !bytes.Contains(output, []byte("--- SKIP:")) {
			t.Fatalf("optional prerequisite did not skip: %s", output)
		}
	}
}

func TestNativeUnavailableFixture(t *testing.T) {
	if os.Getenv("ACS_LINUX_PROBE_SKIP_TEST") == "1" {
		nativeUnavailable(t, "synthetic unavailable prerequisite")
	}
}

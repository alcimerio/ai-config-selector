package linuxprobe

import (
	"bytes"
	"context"
	"os"
	"os/exec"
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
	if !r.PrerequisitesPassed() {
		for _, c := range r.Checks {
			if c.Status != "pass" {
				t.Logf("%s: %s (%s)", c.ID, c.Status, c.Code)
			}
		}
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

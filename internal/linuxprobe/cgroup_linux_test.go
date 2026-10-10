package linuxprobe

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCgroupPathAndMountRejectAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		ok          bool
	}{
		{"0::/user.slice/delegated\n", "user.slice/delegated", true},
		{"0::/\n", ".", true},
		{"0::/../outside", "", false},
		{"0::/user//scope", "", false},
		{"0::/user/./scope", "", false},
		{"0::/private\x00name", "", false},
		{"0::/one\n0::/two", "", false},
		{"2:cpu:/user\n0::/user", "", false},
		{"0::relative", "", false},
	} {
		got, ok := unifiedCgroupPath([]byte(tc.input))
		if got != tc.want || ok != tc.ok {
			t.Errorf("%q: %q %t", tc.input, got, ok)
		}
	}
	for _, tc := range []struct {
		line string
		ok   bool
	}{
		{"36 25 0:32 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw", true},
		{"36 25 0:32 /delegated /sys/fs/cgroup rw - cgroup2 cgroup rw", false},
		{"36 25 0:32 / /sys/fs/cgroup ro - cgroup2 cgroup ro", false},
		{"36 25 0:32 / /sys/fs/cgroup rw - tmpfs cgroup rw", false},
		{"36 25 0:32 / /elsewhere rw - cgroup2 cgroup rw", false},
		{"malformed", false},
	} {
		if standardCgroupMount([]byte(tc.line)) != tc.ok {
			t.Error(tc.line)
		}
	}
}

func TestCgroupEmptinessRequiresBothKernelFacts(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, tc := range []struct {
		events, procs string
		empty, ok     bool
	}{
		{"populated 0\nfrozen 0\n", "", true, true},
		{"populated 1\n", "42\n", false, true},
		{"populated 0\n", "42\n", false, true},
		{"unknown 0\n", "", false, false},
	} {
		for name, contents := range map[string]string{"cgroup.events": tc.events, "cgroup.procs": tc.procs} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
		}
		empty, err := cgroupEmpty(fd)
		if empty != tc.empty || (err == nil) != tc.ok {
			t.Fatalf("%+v: empty=%t err=%v", tc, empty, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "cgroup.events")); err != nil {
		t.Fatal(err)
	}
	if empty, err := cgroupEmpty(fd); err == nil || empty {
		t.Fatal("missing evidence counted as empty")
	}
}

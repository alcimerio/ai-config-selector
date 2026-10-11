package linuxprobe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func healthyProbes() probeOps {
	return probeOps{
		arch: "amd64", uid: 1000, euid: 1000,
		uname: func() (string, string, error) { return "6.12.0-42-generic", "Ubuntu", nil },
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/os-release":
				return []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), nil
			case "/proc/self/status":
				return []byte("NSpid:\t1000\n"), nil
			default:
				return []byte("0::/user.slice/delegated"), nil
			}
		},
		lstat:    func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		getenv:   func(string) string { return "" },
		landlock: func() (int, error) { return 6, nil },
		bwrap:    func() (bwrapIdentity, error) { return bwrapIdentity{}, nil },
		userns:   func(context.Context) error { return nil },
		seccomp:  func(context.Context) error { return nil },
		cgroup:   func(context.Context) error { return nil },
	}
}

func reportCheck(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == "linux."+id {
			return c
		}
	}
	t.Fatalf("missing check %s", id)
	return Check{}
}

func TestProbeAllPrerequisitesAndFailureGates(t *testing.T) {
	r := probeWith(context.Background(), healthyProbes())
	if !r.PrerequisitesPassed() || len(r.Checks) != 10 {
		t.Fatalf("healthy probes: %+v", r)
	}
	private := errors.New("SECRET /home/private/session arbitrary subprocess stderr")
	for _, tc := range []struct {
		name, gate string
		change     func(*probeOps)
	}{
		{"arm64", "architecture", func(p *probeOps) { p.arch = "arm64" }},
		{"root", "privilege", func(p *probeOps) { p.uid, p.euid = 0, 0 }},
		{"setuid", "privilege", func(p *probeOps) { p.euid = 0 }},
		{"old kernel", "kernel", func(p *probeOps) { p.uname = func() (string, string, error) { return "6.11.99", "", nil } }},
		{"unknown kernel", "kernel", func(p *probeOps) { p.uname = func() (string, string, error) { return "SECRET", "", private } }},
		{"release candidate", "kernel", func(p *probeOps) { p.uname = func() (string, string, error) { return "6.12-rc7", "", nil } }},
		{"distribution", "distribution", func(p *probeOps) {
			old := p.readFile
			p.readFile = func(n string) ([]byte, error) {
				if n == "/etc/os-release" {
					return []byte("ID=debian\nVERSION_ID=13"), nil
				}
				return old(n)
			}
		}},
		{"wsl", "environment", func(p *probeOps) {
			p.uname = func() (string, string, error) { return "6.12.0-microsoft-standard-WSL2", "", nil }
		}},
		{"container", "environment", func(p *probeOps) {
			p.getenv = func(n string) string {
				if n == "container" {
					return "SECRET"
				}
				return ""
			}
		}},
		{"missing Landlock", "landlock", func(p *probeOps) { p.landlock = func() (int, error) { return 0, unix.ENOSYS } }},
		{"disabled Landlock", "landlock", func(p *probeOps) { p.landlock = func() (int, error) { return 0, unix.EOPNOTSUPP } }},
		{"old Landlock", "landlock", func(p *probeOps) { p.landlock = func() (int, error) { return 5, nil } }},
		{"Landlock error", "landlock", func(p *probeOps) { p.landlock = func() (int, error) { return 6, private } }},
		{"bwrap", "bwrap", func(p *probeOps) { p.bwrap = func() (bwrapIdentity, error) { return bwrapIdentity{}, private } }},
		{"userns denied", "userns", func(p *probeOps) { p.userns = func(context.Context) error { return unix.EPERM } }},
		{"seccomp denied", "seccomp", func(p *probeOps) { p.seccomp = func(context.Context) error { return private } }},
		{"no delegation", "cgroup_v2", func(p *probeOps) { p.cgroup = func(context.Context) error { return private } }},
		{"cleanup unproven", "cgroup_v2", func(p *probeOps) { p.cgroup = func(context.Context) error { return errCgroupCleanup } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := healthyProbes()
			tc.change(&p)
			r := probeWith(context.Background(), p)
			if r.PrerequisitesPassed() || reportCheck(t, r, tc.gate).Status != "fail" {
				t.Fatalf("gate accepted: %+v", r)
			}
			data, _ := json.Marshal(r)
			for _, value := range []string{"SECRET", "/home/private", "arbitrary subprocess stderr"} {
				if strings.Contains(string(data), value) {
					t.Fatalf("private diagnostic: %s", data)
				}
			}
		})
	}
}

func TestUnsupportedHostAndCancellationRunNoActiveProbes(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		p := healthyProbes()
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		} else {
			p.arch = "arm64"
		}
		p.userns = func(context.Context) error { t.Fatal("active userns"); return nil }
		p.seccomp = func(context.Context) error { t.Fatal("active seccomp"); return nil }
		p.cgroup = func(context.Context) error { t.Fatal("active cgroup"); return nil }
		r := probeWith(ctx, p)
		cancel()
		if r.PrerequisitesPassed() {
			t.Fatal("unobserved host accepted")
		}
		for _, id := range []string{"userns", "seccomp", "cgroup_v2"} {
			if c := reportCheck(t, r, id); c.Status != "unchecked" {
				t.Fatal(c)
			}
		}
	}
}

func TestKernelAndDistributionParsing(t *testing.T) {
	for _, version := range []string{"6.12", "6.12.0-42-generic", "6.12.94+", "7.0.1"} {
		if _, _, _, ok := parseKernelRelease(version); !ok {
			t.Errorf("rejected %q", version)
		}
	}
	for _, version := range []string{"", "6", "6.12-rc1", "6.12.0-rc3", "6.x.1", "6.12.0.1", "-6.12", "6..12", strings.Repeat("9", 129)} {
		if _, _, _, ok := parseKernelRelease(version); ok {
			t.Errorf("accepted %q", version)
		}
	}
	for _, data := range []string{"ID=ubuntu\nVERSION_ID=\"24.04\"", "ID='ubuntu'\nVERSION_ID='24.04'"} {
		if !ubuntu2404([]byte(data)) {
			t.Fatal(data)
		}
	}
	for _, data := range []string{"ID_LIKE=ubuntu\nVERSION_ID=24.04", "ID=ubuntu\nVERSION_ID=22.04", "ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04", "ID=ubuntu\nVERSION_ID=$(echo 24.04)"} {
		if ubuntu2404([]byte(data)) {
			t.Fatal(data)
		}
	}
}

func TestEnvironmentDetectionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*probeOps)
	}{
		{"native", "native_host", func(*probeOps) {}},
		{"WSL env", "wsl_unsupported", func(p *probeOps) {
			p.getenv = func(n string) string {
				if n == "WSL_INTEROP" {
					return "private"
				}
				return ""
			}
		}},
		{"docker marker", "container_unsupported", func(p *probeOps) {
			p.lstat = func(n string) (os.FileInfo, error) {
				if n == "/.dockerenv" {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
		}},
		{"podman marker", "container_unsupported", func(p *probeOps) {
			p.lstat = func(n string) (os.FileInfo, error) {
				if n == "/run/.containerenv" {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
		}},
		{"systemd marker", "container_unsupported", func(p *probeOps) {
			p.lstat = func(n string) (os.FileInfo, error) {
				if n == "/run/systemd/container" {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
		}},
		{"marker unreadable", "environment_unknown", func(p *probeOps) { p.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission } }},
		{"proc unreadable", "environment_unknown", func(p *probeOps) { p.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission } }},
		{"nested pid namespace", "container_unsupported", func(p *probeOps) {
			p.readFile = func(string) ([]byte, error) { return []byte("NSpid:\t4000\t1\n"), nil }
		}},
		{"kubernetes", "container_unsupported", func(p *probeOps) {
			p.readFile = func(string) ([]byte, error) { return []byte("0::/kubepods.slice/private"), nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := healthyProbes()
			tc.change(&p)
			if got := inspectEnvironment(p, "6.12.0", "Ubuntu"); got != tc.want {
				t.Fatalf("%s != %s", got, tc.want)
			}
		})
	}
}

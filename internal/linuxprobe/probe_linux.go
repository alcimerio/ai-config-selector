package linuxprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const minLandlockABI = 6

type probeOps struct {
	arch            string
	uid, euid       int
	uname           func() (release, version string, err error)
	readFile        func(string) ([]byte, error)
	lstat           func(string) (os.FileInfo, error)
	getenv          func(string) string
	landlock        func() (int, error)
	bwrap           func() (bwrapIdentity, error)
	userns, seccomp func(context.Context) error
	cgroup          func(context.Context) error
}

func probe(ctx context.Context) Report {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return probeWith(ctx, probeOps{
		arch: runtime.GOARCH, uid: os.Getuid(), euid: os.Geteuid(),
		uname: kernelVersion, readFile: readSmallFile, lstat: os.Lstat, getenv: os.Getenv,
		landlock: landlockABI, bwrap: inspectBwrap,
		userns: probeUserNamespaces, seccomp: probeSeccomp, cgroup: probeCgroup,
	})
}

func probeWith(ctx context.Context, p probeOps) Report {
	r := Report{}
	add := func(id string, ok bool, code, next string) {
		status := "fail"
		if ok {
			status = "pass"
		}
		r.Checks = append(r.Checks, Check{"linux." + id, status, code, next})
	}
	add("architecture", p.arch == "amd64", "amd64_required", "Initial Linux qualification requires native linux/amd64; arm64 is deferred.")
	add("privilege", p.uid > 0 && p.euid == p.uid, "unprivileged_user_required", "Run as an ordinary user with matching real and effective IDs; root is not a substitute for delegation or user namespaces.")
	release, version, err := p.uname()
	major, minor, patch, valid := parseKernelRelease(release)
	kernelOK := err == nil && valid && (major > 6 || major == 6 && minor >= 12)
	if err == nil && valid {
		add("kernel", kernelOK, "kernel_6_12_required", fmt.Sprintf("Observed kernel %d.%d.%d; Linux 6.12 or newer is required.", major, minor, patch))
	} else {
		add("kernel", false, "kernel_unknown", "The kernel version could not be established.")
	}
	osRelease, err := p.readFile("/etc/os-release")
	add("distribution", err == nil && ubuntu2404(osRelease), "ubuntu_24_04_required", "The initial qualification target is Ubuntu 24.04 with a qualifying HWE kernel; distribution identity alone does not establish support.")
	environmentCode := inspectEnvironment(p, release, version)
	add("environment", environmentCode == "native_host", environmentCode, "WSL and containers are unsupported; use a native host with readable host metadata.")
	// Do not create namespaces, install filters, or touch cgroups on a host that
	// has already failed the platform gates. Read-only feature facts still help.
	hostOK := r.PrerequisitesPassed()
	abi, err := p.landlock()
	switch {
	case errors.Is(err, unix.EOPNOTSUPP):
		add("landlock", false, "landlock_disabled", "Landlock is disabled; enable it through the host's supported LSM configuration.")
	case err != nil:
		add("landlock", false, "landlock_unavailable", "The Landlock ABI query failed; ABI 6 or newer must be available.")
	default:
		add("landlock", abi >= minLandlockABI, "landlock_abi", fmt.Sprintf("Observed Landlock ABI %d; ABI 6 or newer is required. This query does not prove filesystem policy enforcement.", abi))
	}
	_, err = p.bwrap()
	add("bwrap", err == nil, "bwrap_trusted_identity", "Require /usr/bin/bwrap and every parent to be root-owned, inaccessible for user writes, and free of symlinks; the executable must not be setuid or setgid. PATH is never searched.")
	for _, active := range []struct {
		id, code, next string
		run            func(context.Context) error
	}{
		{"userns", "user_namespaces", "A disposable helper must create user, mount and PID namespaces as the calling user. Host policy or namespace quotas may deny this.", p.userns},
		{"seccomp", "seccomp_filter", "A disposable helper must install an architecture-checked seccomp filter with no-new-privileges and observe an allowed and a denied syscall.", p.seccomp},
		{"cgroup_v2", "cgroup_delegation", "Require an owned delegated cgroup v2 subtree: create a child, place a helper in it, kill it, observe populated=0, and remove the child. No Session is created.", p.cgroup},
	} {
		if !hostOK || ctx.Err() != nil {
			code := "host_prerequisites_failed"
			if ctx.Err() != nil {
				code = "probe_cancelled"
			}
			r.Checks = append(r.Checks, Check{"linux." + active.id, "unchecked", code, "No active probe ran; correct the host prerequisites and retry."})
			continue
		}
		err := active.run(ctx)
		code := active.code
		next := active.next
		if errors.Is(err, errCgroupCleanup) {
			code = "cgroup_cleanup_unproven"
			next = "The disposable probe cgroup could not be proven empty or removed. Inspect the delegated subtree for acs-probe-* before retrying; cleanup is unproven."
		}
		add(active.id, err == nil, code, next)
	}
	return r
}

func kernelVersion() (string, string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", "", err
	}
	return unix.ByteSliceToString(u.Release[:]), unix.ByteSliceToString(u.Version[:]), nil
}

func parseKernelRelease(release string) (major, minor, patch int, ok bool) {
	if len(release) == 0 || len(release) > 128 || strings.Contains(strings.ToLower(release), "-rc") {
		return
	}
	for _, r := range release {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '_' || r == '+') {
			return
		}
	}
	base := release
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	parts := strings.Split(base, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return
	}
	numbers := [3]int{}
	for i, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return
		}
		n, err := strconv.Atoi(part)
		if err != nil || n > 1_000_000 {
			return
		}
		numbers[i] = n
	}
	return numbers[0], numbers[1], numbers[2], true
}

func ubuntu2404(data []byte) bool {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return false
		}
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	return values["ID"] == "ubuntu" && values["VERSION_ID"] == "24.04"
}

func inspectEnvironment(p probeOps, release, version string) string {
	if strings.Contains(strings.ToLower(release+" "+version), "microsoft") || strings.Contains(strings.ToLower(release), "wsl") || p.getenv("WSL_INTEROP") != "" || p.getenv("WSL_DISTRO_NAME") != "" {
		return "wsl_unsupported"
	}
	if p.getenv("container") != "" {
		return "container_unsupported"
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := p.lstat(path); err == nil {
			return "container_unsupported"
		} else if !errors.Is(err, os.ErrNotExist) {
			return "environment_unknown"
		}
	}
	for _, path := range []string{"/proc/1/cgroup", "/proc/self/cgroup"} {
		data, err := p.readFile(path)
		if err != nil {
			return "environment_unknown"
		}
		lower := strings.ToLower(string(data))
		for _, token := range []string{"docker", "kubepods", "containerd", "libpod", "lxc", "buildkit"} {
			if strings.Contains(lower, token) {
				return "container_unsupported"
			}
		}
	}
	data, err := p.readFile("/proc/self/status")
	if err != nil {
		return "environment_unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return "environment_unknown"
			}
			for _, field := range fields[1:] {
				pid, err := strconv.Atoi(field)
				if err != nil || pid <= 0 {
					return "environment_unknown"
				}
			}
			if len(fields) > 2 {
				return "container_unsupported"
			}
			return "native_host"
		}
	}
	return "environment_unknown"
}

func landlockABI() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(abi), nil
}

func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err == nil && len(data) > 64*1024 {
		err = errors.New("probe metadata exceeds limit")
	}
	return data, err
}

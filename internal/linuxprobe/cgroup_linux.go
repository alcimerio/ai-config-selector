package linuxprobe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errCgroupCleanup = errors.New("probe cgroup cleanup could not be proven")

// OpenDelegatedCgroup pins the calling user's owned cgroup v2 delegation.
// Callers may create private children here, but must never move existing host
// processes or treat a successful open as proof of sandbox readiness.
func OpenDelegatedCgroup() (*os.File, error) {
	fd, err := delegatedCgroup()
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "acs-delegated-cgroup"), nil
}

func probeCgroup(ctx context.Context) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	parent, err := delegatedCgroup()
	if err != nil {
		return errProbe
	}
	defer unix.Close(parent)
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errProbe
	}
	name := "acs-probe-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(parent, name, 0700); err != nil {
		return errProbe
	}
	// Remove only our freshly created, pinned child, and only when the kernel
	// reports it empty. Never delete or move a preexisting cgroup or process.
	child, err := openCgroupAt(parent, name)
	if err != nil {
		if unix.Unlinkat(parent, name, unix.AT_REMOVEDIR) != nil {
			return errCgroupCleanup
		}
		return errProbe
	}
	defer unix.Close(child)
	defer func() {
		empty, err := cgroupEmpty(child)
		if err != nil || !empty || unix.Unlinkat(parent, name, unix.AT_REMOVEDIR) != nil {
			result = errCgroupCleanup
		}
	}()
	if empty, err := cgroupEmpty(child); err != nil || !empty {
		return errProbe
	}
	input, keepOpen, err := os.Pipe()
	if err != nil {
		return errProbe
	}
	defer input.Close()
	defer keepOpen.Close()
	cmd := helperCommand(ctx, "cgroup")
	cmd.Stdin = input
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: child}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return errProbe
	}
	if err := cmd.Start(); err != nil {
		return errProbe
	}
	// Every post-start path kills and reaps the owned helper, including timeouts.
	waited := false
	defer func() {
		if !waited {
			_ = writeCgroupAt(child, "cgroup.kill", "1")
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	receipt := make([]byte, len(helperReceipt))
	if _, err := io.ReadFull(output, receipt); err != nil || string(receipt) != helperReceipt {
		return errProbe
	}
	procs, err := readCgroupAt(child, "cgroup.procs")
	if err != nil || strings.TrimSpace(string(procs)) != strconv.Itoa(cmd.Process.Pid) {
		return errProbe
	}
	if empty, err := cgroupEmpty(child); err != nil || empty {
		return errProbe
	}
	if err := writeCgroupAt(child, "cgroup.kill", "1"); err != nil {
		return errProbe
	}
	err = cmd.Wait()
	waited = true
	if cmd.ProcessState == nil {
		return errProbe
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if err == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		return errProbe
	}
	// Wait is not itself settlement proof. cgroup.events and membership must
	// also agree; no live descendants are created by this fixed helper.
	if empty, err := cgroupEmpty(child); err != nil || !empty {
		return errCgroupCleanup
	}
	return nil
}

func delegatedCgroup() (int, error) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return -1, errProbe
	}
	mounts, err := readSmallFile("/proc/self/mountinfo")
	if err != nil || !standardCgroupMount(mounts) {
		return -1, errProbe
	}
	data, err := readSmallFile("/proc/self/cgroup")
	if err != nil {
		return -1, errProbe
	}
	relative, ok := unifiedCgroupPath(data)
	if !ok {
		return -1, errProbe
	}
	root, err := unix.Open("/sys/fs/cgroup", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(root)
	var fs unix.Statfs_t
	if unix.Fstatfs(root, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return -1, errProbe
	}
	fd, err := openCgroupAt(root, relative)
	if err != nil {
		return -1, err
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Uid != uint32(os.Geteuid()) || s.Mode&0022 != 0 {
		unix.Close(fd)
		return -1, errProbe
	}
	// Ownership of both the directory and migration control is our delegation
	// boundary. Mere write access to an arbitrary systemd-owned group is not.
	if unix.Fstatat(fd, "cgroup.procs", &s, unix.AT_SYMLINK_NOFOLLOW) != nil || s.Uid != uint32(os.Geteuid()) || s.Mode&0022 != 0 {
		unix.Close(fd)
		return -1, errProbe
	}
	typeData, err := readCgroupAt(fd, "cgroup.type")
	if err != nil || strings.TrimSpace(string(typeData)) != "domain" {
		unix.Close(fd)
		return -1, errProbe
	}
	return fd, nil
}

func standardCgroupMount(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[4] != "/sys/fs/cgroup" {
			continue
		}
		for i := 6; i+3 < len(fields); i++ {
			if fields[i] == "-" {
				return fields[3] == "/" && fields[i+1] == "cgroup2" && strings.Contains(","+fields[5]+",", ",rw,")
			}
		}
	}
	return false
}

func unifiedCgroupPath(data []byte) (string, bool) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "0::/") {
		return "", false
	}
	absolute := strings.TrimPrefix(lines[0], "0::")
	if path.Clean(absolute) != absolute || strings.ContainsAny(absolute, "\x00\r\t\\") {
		return "", false
	}
	if absolute == "/" {
		return ".", true
	}
	return strings.TrimPrefix(absolute, "/"), true
}

func openCgroupAt(parent int, name string) (int, error) {
	return unix.Openat2(parent, name, &unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func readCgroupAt(parent int, name string) ([]byte, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "cgroup-control")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if len(data) > 4096 {
		return nil, errProbe
	}
	return data, err
}

func writeCgroupAt(parent int, name, value string) error {
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	n, err := unix.Write(fd, []byte(value))
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}
	return err
}

func cgroupEmpty(fd int) (bool, error) {
	events, err := readCgroupAt(fd, "cgroup.events")
	if err != nil {
		return false, err
	}
	procs, err := readCgroupAt(fd, "cgroup.procs")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(events), "\n") {
		if line == "populated 0" {
			return strings.TrimSpace(string(procs)) == "", nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errProbe
}

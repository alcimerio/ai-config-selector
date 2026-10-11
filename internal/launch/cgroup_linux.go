package launch

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"golang.org/x/sys/unix"
)

var errLinuxContainment = errors.New("Linux Session containment failed")
var errLinuxSettlement = errors.New("Linux Session cleanup unproven; retain quarantine")

// Keep both the fail-closed category and the underlying syscall available to
// callers. Setup diagnostics must never include argv or environment values.
func linuxStepError(category error, step string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", category, step)
	}
	return fmt.Errorf("%w: %s: %w", category, step, cause)
}

// Only the dedicated, trusted outer supervisor owns these descriptors. Neither
// the target nor the namespace helper may inherit cgroup migration handles.
type linuxSessionCgroup struct {
	parent, directory, kill, events, procs *os.File
	name                                   string
	device, inode                          uint64
}

func linuxNewSessionCgroup() (*linuxSessionCgroup, error) {
	parent, err := linuxprobe.OpenDelegatedCgroup()
	if err != nil {
		return nil, linuxStepError(errLinuxContainment, "open delegated cgroup", err)
	}
	return linuxCreateSessionCgroup(parent)
}

// Takes ownership of an already verified delegation descriptor. There is no
// path or environment override, and no fallback to a process group.
func linuxCreateSessionCgroup(parent *os.File) (_ *linuxSessionCgroup, resultErr error) {
	probe, err := linuxAllocateSessionCgroup(parent)
	if err != nil {
		return nil, err
	}
	defer probe.close()
	// A kill write changes the kernel's kill sequence even on an empty group.
	// Linux 6.17's CLONE_INTO_CGROUP path can compare the parent's sequence with
	// the destination's and SIGKILL a new child before exec. Exercise the real
	// kill control on a disposable sibling; never reuse a killed group to start
	// the Session. Placement remains atomic and settlement still requires kill.
	killErr := probe.terminate()
	if err := probe.remove(); err != nil {
		return nil, errors.Join(killErr, linuxStepError(errLinuxSettlement, "remove kill-preflight cgroup", err))
	}
	if killErr != nil {
		return nil, linuxStepError(errLinuxContainment, "preflight cgroup.kill", killErr)
	}
	fd, err := unix.FcntlInt(probe.parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, linuxStepError(errLinuxContainment, "pin delegation after kill preflight", err)
	}
	return linuxAllocateSessionCgroup(os.NewFile(uintptr(fd), "acs-delegated-cgroup"))
}

func linuxAllocateSessionCgroup(parent *os.File) (_ *linuxSessionCgroup, resultErr error) {
	g := &linuxSessionCgroup{parent: parent}
	defer func() {
		if resultErr != nil {
			g.close()
		}
	}()
	var fs unix.Statfs_t
	if parent == nil {
		return nil, linuxStepError(errLinuxContainment, "missing delegated cgroup", nil)
	}
	if err := unix.Fstatfs(int(parent.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, linuxStepError(errLinuxContainment, "verify cgroup v2 filesystem", err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, linuxStepError(errLinuxContainment, "generate cgroup name", err)
	}
	g.name = "acs-session-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(int(parent.Fd()), g.name, 0700); err != nil {
		return nil, linuxStepError(errLinuxContainment, "create Session cgroup", err)
	}
	// Until a child starts, only this freshly created empty directory can exist.
	defer func() {
		if resultErr != nil {
			if err := unix.Unlinkat(int(parent.Fd()), g.name, unix.AT_REMOVEDIR); err != nil {
				resultErr = errors.Join(resultErr, linuxStepError(errLinuxSettlement, "remove incomplete cgroup", err))
			}
		}
	}()
	fd, err := unix.Openat2(int(parent.Fd()), g.name, &unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, linuxStepError(errLinuxContainment, "open Session cgroup", err)
	}
	g.directory = os.NewFile(uintptr(fd), "acs-session-cgroup")
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, linuxStepError(errLinuxContainment, "stat Session cgroup", err)
	}
	g.device, g.inode = uint64(stat.Dev), stat.Ino
	for _, item := range []struct {
		name string
		mode int
		file **os.File
	}{
		{"cgroup.kill", unix.O_WRONLY, &g.kill},
		{"cgroup.events", unix.O_RDONLY, &g.events},
		{"cgroup.procs", unix.O_RDONLY, &g.procs},
	} {
		control, err := unix.Openat(fd, item.name, item.mode|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, linuxStepError(errLinuxContainment, "open "+item.name, err)
		}
		*item.file = os.NewFile(uintptr(control), item.name)
	}
	// A Session is a leaf. This is defense in depth; the private mount view and
	// descriptor sealing must also deny all access to cgroup migration controls.
	depth, err := unix.Openat(fd, "cgroup.max.depth", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, linuxStepError(errLinuxContainment, "open cgroup.max.depth", err)
	}
	n, err := unix.Write(depth, []byte("0"))
	_ = unix.Close(depth)
	if err != nil || n != 1 {
		return nil, linuxStepError(errLinuxContainment, "write cgroup.max.depth=0", err)
	}
	if empty, err := g.empty(); err != nil || !empty {
		return nil, linuxStepError(errLinuxContainment, "verify new cgroup is empty", err)
	}
	return g, nil
}

func (g *linuxSessionCgroup) identity() error {
	var named, pinned unix.Stat_t
	if err := unix.Fstatat(int(g.parent.Fd()), g.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return linuxStepError(errLinuxSettlement, "stat named cgroup", err)
	}
	if err := unix.Fstat(int(g.directory.Fd()), &pinned); err != nil {
		return linuxStepError(errLinuxSettlement, "stat pinned cgroup", err)
	}
	if uint64(named.Dev) != g.device || named.Ino != g.inode || named.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(pinned.Dev) != g.device || pinned.Ino != g.inode || pinned.Nlink == 0 {
		return linuxStepError(errLinuxSettlement, "cgroup identity changed", nil)
	}
	return nil
}

func linuxReadCgroupControl(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", linuxStepError(errLinuxSettlement, "seek "+file.Name(), err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return "", linuxStepError(errLinuxSettlement, "read "+file.Name(), err)
	}
	return string(data), nil
}

func linuxCgroupUnpopulated(events, procs string) (bool, error) {
	found, empty := false, false
	for _, line := range strings.Split(events, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "populated" {
			continue
		}
		if found || len(fields) != 2 || fields[1] != "0" && fields[1] != "1" {
			return false, errLinuxSettlement
		}
		found, empty = true, fields[1] == "0"
	}
	if !found {
		return false, errLinuxSettlement
	}
	return empty && strings.TrimSpace(procs) == "", nil
}

func (g *linuxSessionCgroup) empty() (bool, error) {
	if err := g.identity(); err != nil {
		return false, err
	}
	events, err := linuxReadCgroupControl(g.events)
	if err != nil {
		return false, err
	}
	procs, err := linuxReadCgroupControl(g.procs)
	if err != nil {
		return false, err
	}
	return linuxCgroupUnpopulated(events, procs)
}

func (g *linuxSessionCgroup) contains(pid int) error {
	if err := g.identity(); err != nil {
		return err
	}
	procs, err := linuxReadCgroupControl(g.procs)
	if err != nil {
		return err
	}
	for _, entry := range strings.Fields(procs) {
		if entry == strconv.Itoa(pid) {
			return nil
		}
	}
	return linuxStepError(errLinuxContainment, "leader absent from cgroup.procs", nil)
}

func (g *linuxSessionCgroup) terminate() error {
	if err := g.identity(); err != nil {
		return err
	}
	n, err := g.kill.WriteAt([]byte("1"), 0)
	if err != nil || n != 1 {
		return linuxStepError(errLinuxSettlement, "write cgroup.kill=1", err)
	}
	return nil
}

func (g *linuxSessionCgroup) remove() error {
	if empty, err := g.empty(); err != nil || !empty {
		return errLinuxSettlement
	}
	if err := unix.Unlinkat(int(g.parent.Fd()), g.name, unix.AT_REMOVEDIR); err != nil {
		return linuxStepError(errLinuxSettlement, "remove empty cgroup", err)
	}
	return nil
}

func (g *linuxSessionCgroup) close() {
	for _, f := range []*os.File{g.procs, g.events, g.kill, g.directory, g.parent} {
		if f != nil {
			_ = f.Close()
		}
	}
}

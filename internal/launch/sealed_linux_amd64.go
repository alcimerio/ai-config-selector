package launch

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"golang.org/x/sys/unix"
)

const linuxTransportLimit = 2 << 20
const linuxTransportSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

type linuxWireRule struct {
	Path   string
	Access uint64
}

// Private descriptor protocol, not a CLI or a persistent policy format. Only
// the test executable contains an entry point for consuming this protocol.
type linuxLaunchWire struct {
	Version                    int
	Rules                      []linuxWireRule
	Executable                 string
	Argv                       []string
	Home, Temporary, Directory string
	Terminal                   *linuxTerminalConfig `json:",omitempty"`
}

func (w linuxLaunchWire) validate() error {
	if w.Version != 1 || len(w.Rules) == 0 || len(w.Rules) > 8192 || len(w.Argv) == 0 || w.Argv[0] != w.Executable {
		return errLinuxSeal
	}
	for _, path := range []string{w.Executable, w.Home, w.Temporary, w.Directory} {
		if !linuxCanonicalPlanPath(path) {
			return errLinuxSeal
		}
	}
	for _, arg := range w.Argv {
		if strings.ContainsRune(arg, 0) {
			return errLinuxSeal
		}
	}
	for _, rule := range w.Rules {
		if !linuxCanonicalPlanPath(rule.Path) || rule.Access == 0 || rule.Access & ^uint64(linuxHandledFilesystem) != 0 {
			return errLinuxSeal
		}
	}
	return nil
}

func linuxSealedMemfd(data []byte) (*os.File, error) {
	if len(data) > linuxTransportLimit {
		return nil, errLinuxSeal
	}
	fd, err := unix.MemfdCreate("acs-private", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errLinuxSeal
	}
	f := os.NewFile(uintptr(fd), "acs-private")
	if _, err = f.Write(data); err == nil {
		_, err = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, linuxTransportSeals)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = f.Close()
		return nil, errLinuxSeal
	}
	return f, nil
}

func linuxWriteTransport(w linuxLaunchWire, env *environmentresource.Lease) (*os.File, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(w)
	if err != nil || len(metadata) > linuxTransportLimit/2 {
		return nil, errLinuxSeal
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(metadata)))
	_, _ = b.Write(metadata)
	if err := env.WriteFrame(&b); err != nil {
		return nil, errLinuxSeal
	}
	defer clear(b.Bytes())
	return linuxSealedMemfd(b.Bytes())
}

func linuxReadTransport(f *os.File) (linuxLaunchWire, []string, error) {
	fail := func() (linuxLaunchWire, []string, error) { return linuxLaunchWire{}, nil, errLinuxSeal }
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	info, statErr := f.Stat()
	if err != nil || statErr != nil || !info.Mode().IsRegular() || seals != linuxTransportSeals || info.Size() > linuxTransportLimit {
		return fail()
	}
	reader := io.LimitReader(f, linuxTransportLimit+1)
	var size uint32
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || size > linuxTransportLimit/2 {
		return fail()
	}
	metadata := make([]byte, size)
	if _, err := io.ReadFull(reader, metadata); err != nil {
		return fail()
	}
	var w linuxLaunchWire
	d := json.NewDecoder(bytes.NewReader(metadata))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil || w.validate() != nil || d.Decode(new(any)) != io.EOF {
		return fail()
	}
	intrinsic := []string{"HOME=" + w.Home, "TMPDIR=" + w.Temporary, "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
		"XDG_CONFIG_HOME=" + w.Home + "/.config", "XDG_DATA_HOME=" + w.Home + "/.local/share",
		"XDG_CACHE_HOME=" + w.Home + "/.cache", "XDG_STATE_HOME=" + w.Home + "/.local/state"}
	if w.Terminal != nil {
		intrinsic = append(intrinsic, "TERM=xterm")
	}
	selected, err := environmentresource.ReadFrame(reader, intrinsic)
	if err != nil {
		return fail()
	}
	var tail [1]byte
	if n, err := reader.Read(tail[:]); n != 0 || err != io.EOF {
		return fail()
	}
	return w, append(intrinsic, selected...), nil
}

// linuxPinnedSource binds the same inode that was compiled, without a pathname
// re-open by bwrap. Changes to directory contents remain governed by the private
// mount view, nodev/read-only binds, Landlock, and socket denial, not by a scan.
func linuxPinnedSource(m linuxMount) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, m.source, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, errLinuxSeal
	}
	f := os.NewFile(uintptr(fd), "linux-source")
	info, err := f.Stat()
	var statx unix.Statx_t
	if err != nil || unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &statx) != nil ||
		statx.Mask&unix.STATX_MNT_ID == 0 || statx.Mnt_id != m.mountID {
		_ = f.Close()
		return nil, errLinuxSeal
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identityFromFileInfo(info, stat) != m.identity {
		_ = f.Close()
		return nil, errLinuxSeal
	}
	return f, nil
}

type linuxBwrapLaunch struct {
	command *exec.Cmd
	owned   []*os.File
}

func (p *linuxBwrapLaunch) close() {
	for _, f := range p.owned {
		_ = f.Close()
	}
	p.owned = nil
}

// Prepares but never starts a process. No production caller or backend registers
// this launcher. The native harness alone supplies the test helper entry point;
// it also owns cgroup placement and proof of emptiness for the composed tests.
func linuxPrepareBwrap(ctx context.Context, plan linuxFilesystemPlan, wire linuxLaunchWire, env *environmentresource.Lease,
	helper, status, gate *os.File, stdio [3]*os.File, helperArgs []string) (_ *linuxBwrapLaunch, resultErr error) {
	return linuxPrepareBwrapWith(ctx, plan, wire, env, helper, status, gate, stdio, helperArgs, linuxprobe.OpenSystemBwrap)
}

func linuxPrepareBwrapWith(ctx context.Context, plan linuxFilesystemPlan, wire linuxLaunchWire, env *environmentresource.Lease,
	helper, status, gate *os.File, stdio [3]*os.File, helperArgs []string, openBwrap func() (*os.File, error)) (_ *linuxBwrapLaunch, resultErr error) {
	p := &linuxBwrapLaunch{}
	step := "validate filesystem plan and transport"
	defer func() {
		if resultErr != nil {
			p.close()
			resultErr = linuxStepError(errLinuxSeal, "prepare Bubblewrap: "+step, resultErr)
		}
	}()
	if helper == nil || status == nil || gate == nil || wire.validate() != nil || plan.handledAccess != linuxHandledFilesystem || plan.scoped != 3 ||
		plan.unixSockets != linuxUnixSocketsDenyCreation || len(plan.mounts) < 2 ||
		plan.mounts[len(plan.mounts)-1] != (linuxMount{kind: linuxMountSealRoot, destination: "/"}) {
		return nil, errLinuxSeal
	}
	// The transmitted rules must be exactly the compiled authority.
	if len(plan.rules) != len(wire.Rules) {
		return nil, errLinuxSeal
	}
	for i, rule := range plan.rules {
		if wire.Rules[i] != (linuxWireRule{rule.path, rule.access}) {
			return nil, errLinuxSeal
		}
	}
	// These nodes exist only in bwrap's private /dev, never in a host bind.
	wire.Rules = append([]linuxWireRule(nil), wire.Rules...)
	for _, path := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		wire.Rules = append(wire.Rules, linuxWireRule{path, linuxReadFile | linuxWriteFile})
	}
	wire.Rules = append(wire.Rules, linuxWireRule{"/dev/pts", linuxReadTree | linuxWriteFile | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV})
	step = "seal launch transport"
	transport, err := linuxWriteTransport(wire, env)
	if err != nil {
		return nil, err
	}
	p.owned = append(p.owned, transport)
	step = "open trusted system Bubblewrap"
	bwrap, err := openBwrap()
	if err != nil {
		return nil, err
	}
	p.owned = append(p.owned, bwrap)
	var filter bytes.Buffer
	_ = binary.Write(&filter, binary.LittleEndian, linuxSeccompFilterForSetup(wire.Terminal != nil))
	step = "seal setup seccomp filter"
	seccomp, err := linuxSealedMemfd(filter.Bytes())
	if err != nil {
		return nil, err
	}
	p.owned = append(p.owned, seccomp)
	step = "pin stdio"
	pins, err := linuxPinStdio(stdio)
	if err != nil {
		return nil, err
	}
	p.owned = append(p.owned, pins[:]...)
	// FD numbers are private protocol constants, never caller-supplied argv.
	extra := []*os.File{transport, status, gate, bwrap, seccomp, helper}
	args := []string{"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
		"--tmpfs", "/", "--dev", "/dev", "--proc", "/proc", "--ro-bind", "/proc/self/fd/8", "/.acs-launcher"}
	for i, mount := range plan.mounts {
		step = "pin mount " + mount.destination
		if mount.kind == linuxMountSealRoot || i == 0 && mount.kind == linuxMountDirectory && mount.destination == "/" {
			continue
		}
		if !linuxCanonicalPlanPath(mount.destination) || withinOrEqual("/.acs-launcher", mount.destination) || linuxReservedHostTree(mount.destination) {
			return nil, errLinuxSeal
		}
		switch mount.kind {
		case linuxMountDirectory:
			args = append(args, "--dir", mount.destination)
		case linuxMountReadOnly, linuxMountReadWrite, linuxMountRuntimeAlias:
			if mount.source != mount.destination && (mount.kind != linuxMountRuntimeAlias || !mount.identity.mode.IsRegular()) {
				return nil, errLinuxSeal
			}
			source, err := linuxPinnedSource(mount)
			if err != nil {
				return nil, err
			}
			p.owned = append(p.owned, source)
			option := "--ro-bind"
			if mount.kind == linuxMountReadWrite {
				option = "--bind"
			}
			args = append(args, option, "/proc/self/fd/"+strconv.Itoa(3+len(extra)), mount.destination)
			extra = append(extra, source)
		default:
			return nil, errLinuxSeal
		}
	}
	args = append(args, "--chdir", wire.Directory, "--remount-ro", "/", "--seccomp", "7", "--", "/.acs-launcher")
	args = append(args, helperArgs...)
	p.command = exec.CommandContext(ctx, "/proc/self/fd/6", args...)
	p.command.Args[0] = "/usr/bin/bwrap"
	p.command.Dir = "/"
	p.command.Env = []string{"LANG=C", "LC_ALL=C"}
	p.command.ExtraFiles = extra
	p.command.Stdin, p.command.Stdout, p.command.Stderr = pins[0], pins[1], pins[2]
	return p, nil
}

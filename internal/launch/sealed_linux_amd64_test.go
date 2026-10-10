package launch

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"golang.org/x/sys/unix"
)

// A small interpreter proves the generated classic-BPF branches, including
// otherwise uncallable foreign architectures and the x32 syscall-number bit.
func linuxEvaluateFilter(t *testing.T, arch, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[:4], nr)
	binary.LittleEndian.PutUint32(data[4:8], arch)
	for i, arg := range args {
		binary.LittleEndian.PutUint64(data[16+i*8:], arg)
	}
	var a uint32
	f := linuxSeccompFilter()
	for pc := 0; pc < len(f); pc++ {
		i := f[pc]
		switch i.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			a = binary.LittleEndian.Uint32(data[i.K:])
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			a &= i.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			match := a == i.K
			if i.Code == unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K {
				match = a&i.K != 0
			}
			if match {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return i.K
		default:
			t.Fatalf("unexpected BPF instruction: %v", i)
		}
	}
	t.Fatal("filter fell through")
	return 0
}

func TestLinuxSeccompPolicy(t *testing.T) {
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for _, nr := range []uint32{
		unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_MKNOD, unix.SYS_MKNODAT,
	} {
		if got := linuxEvaluateFilter(t, unix.AUDIT_ARCH_X86_64, nr, [6]uint64{}); got != deny {
			t.Errorf("syscall %d = %#x", nr, got)
		}
	}
	for _, tc := range []struct {
		nr, want uint32
		args     [6]uint64
	}{
		{unix.SYS_IOCTL, deny, [6]uint64{0, unix.TIOCSTI}},
		{unix.SYS_IOCTL, deny, [6]uint64{0, unix.TIOCLINUX}},
		{unix.SYS_IOCTL, deny, [6]uint64{0, 1<<32 | unix.TIOCSTI}},
		{unix.SYS_IOCTL, deny, [6]uint64{0, unix.TIOCVHANGUP}},
		{unix.SYS_IOCTL, deny, [6]uint64{0, unix.TIOCSCTTY}},
		{unix.SYS_IOCTL, deny, [6]uint64{0, unix.TIOCSETD}},
		{unix.SYS_IOCTL, unix.SECCOMP_RET_ALLOW, [6]uint64{0, unix.TCGETS}},
		{unix.SYS_IOCTL, unix.SECCOMP_RET_ALLOW, [6]uint64{0, unix.TCSETS}},
		{unix.SYS_IOCTL, unix.SECCOMP_RET_ALLOW, [6]uint64{0, unix.TIOCSWINSZ}},
		{unix.SYS_CLONE3, unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS), [6]uint64{}},
		{unix.SYS_CLONE, unix.SECCOMP_RET_ALLOW, [6]uint64{uint64(unix.SIGCHLD)}},
		{unix.SYS_CLONE, unix.SECCOMP_RET_ALLOW, [6]uint64{unix.CLONE_VM | unix.CLONE_THREAD | unix.CLONE_SIGHAND}},
		{unix.SYS_SOCKET, deny, [6]uint64{unix.AF_UNIX}},
		{unix.SYS_SOCKET, deny, [6]uint64{1<<32 | unix.AF_UNIX}},
		{unix.SYS_SOCKET, deny, [6]uint64{unix.AF_NETLINK}},
		{unix.SYS_SOCKET, unix.SECCOMP_RET_ALLOW, [6]uint64{unix.AF_INET}},
		{unix.SYS_SOCKET, unix.SECCOMP_RET_ALLOW, [6]uint64{unix.AF_INET6}},
		{unix.SYS_SOCKETPAIR, unix.SECCOMP_RET_ALLOW, [6]uint64{unix.AF_UNIX, unix.SOCK_STREAM}},
		{unix.SYS_SOCKETPAIR, unix.SECCOMP_RET_ALLOW, [6]uint64{unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK}},
		{unix.SYS_SOCKETPAIR, deny, [6]uint64{unix.AF_UNIX, unix.SOCK_DGRAM}},
		{unix.SYS_SOCKETPAIR, deny, [6]uint64{unix.AF_UNIX, unix.SOCK_SEQPACKET}},
		{unix.SYS_READ, unix.SECCOMP_RET_ALLOW, [6]uint64{}},
		{unix.SYS_EXECVE, unix.SECCOMP_RET_ALLOW, [6]uint64{}},
	} {
		if got := linuxEvaluateFilter(t, unix.AUDIT_ARCH_X86_64, tc.nr, tc.args); got != tc.want {
			t.Errorf("syscall %d args %v = %#x want %#x", tc.nr, tc.args, got, tc.want)
		}
	}
	for _, flag := range []uint64{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWNET,
		unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME} {
		if linuxEvaluateFilter(t, unix.AUDIT_ARCH_X86_64, unix.SYS_CLONE, [6]uint64{flag | uint64(unix.SIGCHLD)}) != deny {
			t.Errorf("clone namespace %#x allowed", flag)
		}
	}
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_AARCH64, 0} {
		if linuxEvaluateFilter(t, arch, unix.SYS_READ, [6]uint64{}) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("foreign architecture allowed")
		}
	}
	if linuxEvaluateFilter(t, unix.AUDIT_ARCH_X86_64, 0x40000000|unix.SYS_READ, [6]uint64{}) != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("x32 allowed")
	}
}

func linuxTestLease(t *testing.T, values map[string]string) *environmentresource.Lease {
	t.Helper()
	var intents []environmentresource.Intent
	for name := range values {
		intents = append(intents, environmentresource.Intent{ID: strings.ToLower(strings.ReplaceAll(name, "_", "-")), Destination: name, Scope: "attached-process-tree",
			SourceKind: "host-environment", SourceName: name, Classification: "non-secret", Required: true})
	}
	lease, err := environmentresource.Resolve(intents, func(k string) (string, bool) { v, ok := values[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	return lease
}

func linuxTestWire() linuxLaunchWire {
	return linuxLaunchWire{Version: 1, Rules: []linuxWireRule{{"/work/project", linuxReadTree}},
		Executable: "/tools/target", Argv: []string{"/tools/target", "literal argument"},
		Home: "/session/home", Temporary: "/session/tmp", Directory: "/work/project"}
}

func TestLinuxPrivateTransport(t *testing.T) {
	t.Setenv("UNSELECTED_SECRET", "ambient-secret")
	want := linuxTestWire()
	f, err := linuxWriteTransport(want, linuxTestLease(t, map[string]string{"SELECTED": "synthetic-secret"}))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, env, err := linuxReadTransport(f)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip: %v", err)
	}
	if !bytes.Contains([]byte(env[len(env)-1]), []byte("SELECTED=synthetic-secret")) || len(env) != 6 {
		t.Fatal("environment selection changed")
	}
	if _, err := f.WriteAt([]byte("x"), 0); err != unix.EPERM && !os.IsPermission(err) {
		t.Fatalf("transport can be changed: %v", err)
	}
	if err := f.Truncate(0); err == nil {
		t.Fatal("transport can be truncated")
	}
	_, _ = f.Seek(0, io.SeekStart)
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, data[:3], data[:len(data)-1], append(append([]byte{}, data...), 'x')} {
		bad, err := linuxSealedMemfd(invalid)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = linuxReadTransport(bad)
		_ = bad.Close()
		if err == nil {
			t.Fatal("malformed transport accepted")
		}
	}
	unsealed, err := os.CreateTemp(t.TempDir(), "transport")
	if err != nil {
		t.Fatal(err)
	}
	defer unsealed.Close()
	_, _ = unsealed.Write(data)
	_, _ = unsealed.Seek(0, io.SeekStart)
	if _, _, err := linuxReadTransport(unsealed); err == nil {
		t.Fatal("mutable transport accepted")
	}
}

func TestLinuxStdioRejectsSocketsAndPinsRedirects(t *testing.T) {
	socket, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socket[0])
	defer unix.Close(socket[1])
	if linuxCheckStdio(socket[0]) == nil {
		t.Fatal("connected Unix socket accepted as stdio")
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if linuxCheckStdio(int(dir.Fd())) == nil {
		t.Fatal("directory accepted as stdio")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "redirect"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := linuxPinStdio([3]*os.File{f, f, f})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	for _, pin := range pins {
		if _, err := pin.Write([]byte("x")); err != nil {
			t.Fatal("pin did not survive original descriptor close")
		}
		flags, err := unix.FcntlInt(pin.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("pin is inheritable")
		}
		_ = pin.Close()
	}
}

func TestLinuxBwrapPreparationPinsSourcesAndUsesPrivateFDs(t *testing.T) {
	// The injected opener mocks only the trusted bwrap identity. Nothing is
	// executed; real source FDs, transport seals and descriptor layout are checked.
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	var x unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, target, 0, unix.STATX_MNT_ID, &x); err != nil {
		t.Fatal(err)
	}
	plan := linuxFilesystemPlan{handledAccess: linuxHandledFilesystem, scoped: 3, unixSockets: linuxUnixSocketsDenyCreation,
		mounts: []linuxMount{{kind: linuxMountDirectory, destination: "/"},
			{kind: linuxMountReadOnly, source: target, destination: target, identity: identityFromFileInfo(info, info.Sys().(*syscall.Stat_t)), mountID: x.Mnt_id},
			{kind: linuxMountSealRoot, destination: "/"}},
		rules: []linuxLandlockRule{{target, linuxReadFile}}}
	w := linuxTestWire()
	w.Executable, w.Argv, w.Rules = target, []string{target}, []linuxWireRule{{target, linuxReadFile}}
	lease := linuxTestLease(t, map[string]string{"SELECTED": "private-value"})
	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	open := func() (*os.File, error) { return os.Open("/proc/self/exe") }
	prepare := func(plan linuxFilesystemPlan) (*linuxBwrapLaunch, error) {
		return linuxPrepareBwrapWith(context.Background(), plan, w, lease, file, file, file,
			[3]*os.File{file, file, file}, []string{"test-entry"}, open)
	}
	p, err := prepare(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	cmd := p.command
	if cmd.Path != "/proc/self/fd/6" || cmd.Process != nil || !reflect.DeepEqual(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) {
		t.Fatal("preparation used an unpinned executable, inherited env, or started a process")
	}
	args := strings.Join(cmd.Args, "\x00")
	for _, want := range []string{"--unshare-user", "--unshare-pid", "--unshare-cgroup", "--new-session", "--disable-userns",
		"--cap-drop\x00ALL", "--clearenv", "--proc\x00/proc", "--dev\x00/dev", "--remount-ro\x00/", "--seccomp\x007", "--ro-bind\x00/proc/self/fd/9"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing bwrap restriction %q", want)
		}
	}
	for _, forbidden := range []string{"private-value", "SELECTED", "--setenv", "--try", "--as-pid-1", "--unshare-net", "--dev-bind", "--not-a-security-boundary"} {
		if strings.Contains(args, forbidden) {
			t.Errorf("unexpected bwrap argument %q", forbidden)
		}
	}
	// A source rename cannot retarget the descriptor already passed to bwrap.
	if err := os.Rename(target, target+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("substitute"), 0700); err != nil {
		t.Fatal(err)
	}
	var pinned unix.Stat_t
	if unix.Fstat(int(cmd.ExtraFiles[6].Fd()), &pinned) != nil || pinned.Ino != plan.mounts[1].identity.inode {
		t.Fatal("source pin was retargeted")
	}
	if bad, err := prepare(plan); err == nil || bad != nil {
		if bad != nil {
			bad.close()
		}
		t.Fatal("changed source accepted")
	}
	badPlan := plan
	badPlan.scoped = 0
	if bad, err := prepare(badPlan); err == nil || bad != nil {
		t.Fatal("incomplete restrictions accepted")
	}
}

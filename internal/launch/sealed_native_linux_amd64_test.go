package launch

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func linuxNativeUnavailable(t *testing.T, reason string) {
	t.Helper()
	if _, required := os.LookupEnv("ACS_LINUX_NATIVE_REQUIRED"); required {
		t.Fatal("required native Linux prerequisite unavailable: " + reason)
	}
	t.Skip("native Linux prerequisite unavailable: " + reason + "; set ACS_LINUX_NATIVE_REQUIRED=1 to require it")
}

func linuxNativePrerequisites(t *testing.T) {
	t.Helper()
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 6 {
		linuxNativeUnavailable(t, "Landlock ABI 6 and Linux 6.12+")
	}
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			linuxNativeUnavailable(t, "static test executable; run with CGO_ENABLED=0")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxSealHelper$", "--", "acs-seal-helper-prerequisite")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := cmd.Run(); err != nil {
		linuxNativeUnavailable(t, "seccomp installation, no-new-privileges and close_range")
	}
}

// Test entry point only: production acs contains no re-exec flag or environment
// switch that can invoke a Linux target. The helper runs only fixed test probes.
func TestLinuxSealHelper(t *testing.T) {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[len(os.Args)-1], "acs-seal-helper") {
		return
	}
	mode := strings.TrimPrefix(os.Args[len(os.Args)-1], "acs-seal-helper")
	if mode == "-prerequisite" {
		filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}}
		program := unix.SockFprog{Len: 1, Filter: &filter[0]}
		if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.CloseRange(1<<30, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) != nil {
			os.Exit(125)
		}
		_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
		runtime.KeepAlive(filter)
		if errno != 0 {
			os.Exit(125)
		}
		os.Exit(0)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		os.Exit(125)
	}
	transport := os.NewFile(3, "transport")
	w, env, err := linuxReadTransport(transport)
	if err != nil {
		os.Exit(125)
	}
	// An intentionally inherited high FD must be removed by the raw boundary.
	if err := unix.Dup3(3, 200, 0); err != nil {
		os.Exit(125)
	}
	_ = transport.Close()
	if denied, inject := map[string]uint32{"-deny-prctl": unix.SYS_PRCTL, "-deny-capset": unix.SYS_CAPSET,
		"-deny-close-range": unix.SYS_CLOSE_RANGE, "-deny-dup3": unix.SYS_DUP3}[mode]; inject {
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: denied, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
			os.Exit(125)
		}
		_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
		runtime.KeepAlive(filter)
		if errno != 0 {
			os.Exit(125)
		}
	}
	rules := make([]linuxLandlockRule, len(w.Rules))
	for i, rule := range w.Rules {
		rules[i] = linuxLandlockRule{rule.Path, rule.Access}
	}
	var pid int
	if mode == "-bad-landlock" || mode == "-bad-seccomp" {
		// Real kernel failure injection, confined to this disposable helper.
		filter := linuxSeccompFilter(false)
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		ruleset, setupErr := linuxLandlockRuleset(rules)
		if setupErr != nil {
			os.Exit(125)
		}
		defer unix.Close(ruleset)
		argv, _ := linuxExecStrings(w.Argv)
		envp, _ := linuxExecStrings(env)
		status, _ := unix.FcntlInt(4, unix.F_DUPFD_CLOEXEC, 128)
		gate, _ := unix.FcntlInt(5, unix.F_DUPFD_CLOEXEC, 128)
		pair, pairErr := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if pairErr != nil {
			os.Exit(125)
		}
		config := linuxExecBoundary{int64(ruleset), int64(status), int64(gate), &program, argv[0], &argv[0], &envp[0], -1, int64(pair[1])}
		if mode == "-bad-landlock" {
			config.ruleset = -1
		} else {
			// Do not collide with the status/gate remap before reaching seccomp.
			copy, copyErr := unix.FcntlInt(uintptr(ruleset), unix.F_DUPFD_CLOEXEC, 128)
			if copyErr != nil {
				os.Exit(125)
			}
			config.ruleset = int64(copy)
			program.Len = 0
		}
		runtime.LockOSThread()
		child, errno := linuxForkExec(&config)
		runtime.UnlockOSThread()
		runtime.KeepAlive(argv)
		runtime.KeepAlive(envp)
		runtime.KeepAlive(filter)
		if errno != 0 {
			os.Exit(125)
		}
		pid = int(child)
		_ = unix.Close(status)
		_ = unix.Close(gate)
	} else {
		pid, err = linuxStartRestrictedTerminal(rules, w.Executable, w.Argv, env, 4, 5, -1, linuxLoopbackPolicy{Ports: w.LoopbackPorts, Callback: w.LoopbackCallback, Resolvers: linuxWireResolvers(w.Resolvers)})
		if err != nil {
			os.Exit(125)
		}
	}
	_ = unix.Close(4)
	_ = unix.Close(5)
	var status unix.WaitStatus
	for {
		_, err = unix.Wait4(pid, &status, 0, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil || !status.Exited() {
		os.Exit(125)
	}
	os.Exit(status.ExitStatus())
}

func TestLinuxSealProbe(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "acs-seal-probe" {
		return
	}
	base := os.Getenv("PROBE_ROOT")
	if err := os.WriteFile(filepath.Join(base, "output", "started"), []byte("started"), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SELECTED") != "synthetic-secret" || os.Getenv("UNSELECTED_SECRET") != "" {
		t.Fatal("incorrect selected environment")
	}
	if _, err := unix.FcntlInt(200, unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatal("inherited descriptor survived")
	}
	if v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil || v != 1 {
		t.Fatal("no-new-privileges missing")
	}
	var header = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&header, &caps[0]) != nil || caps != [2]unix.CapUserData{} {
		t.Fatal("capabilities survived")
	}
	if data, err := os.ReadFile(filepath.Join(base, "work", "allowed")); err != nil || string(data) != "allowed" {
		t.Fatal("read-only positive control failed")
	}
	if err := os.WriteFile(filepath.Join(base, "work", "allowed"), []byte("changed"), 0600); err == nil {
		t.Fatal("read-only write allowed")
	}
	if _, err := os.ReadFile(filepath.Join(base, "host-canary")); err == nil {
		t.Fatal("ungranted read allowed")
	}
	output := filepath.Join(base, "output", "created")
	if err := os.WriteFile(output, []byte("allowed-write"), 0600); err != nil {
		t.Fatal("write positive control:", err)
	}
	if err := os.Rename(output, output+"-renamed"); err != nil {
		t.Fatal("rename positive control:", err)
	}
	for _, nr := range []uintptr{unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_PTRACE,
		unix.SYS_KEYCTL, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_MOUNT, unix.SYS_UNSHARE,
		unix.SYS_MOVE_MOUNT, unix.SYS_PIDFD_GETFD, unix.SYS_IO_URING_SETUP} {
		if _, _, errno := unix.RawSyscall6(nr, ^uintptr(0), 0, 0, 0, 0, 0); errno != unix.EPERM {
			t.Errorf("syscall %d did not return policy EPERM: %v", nr, errno)
		}
	}
	for _, request := range []uintptr{unix.TIOCSTI, unix.TIOCLINUX, unix.TIOCVHANGUP, 1<<32 | unix.TIOCSTI} {
		if _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, 0, request, 0); errno != unix.EPERM {
			t.Errorf("terminal ioctl %#x was not denied: %v", request, errno)
		}
	}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0); err != unix.EPERM {
		_ = unix.Close(fd)
		t.Fatal("Unix socket creation allowed")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal("private socketpair positive control:", err)
	}
	if _, err := unix.Write(pair[0], []byte{'p'}); err != nil {
		t.Fatal(err)
	}
	var ipc [1]byte
	if n, err := unix.Read(pair[1], ipc[:]); err != nil || n != 1 || ipc[0] != 'p' {
		t.Fatal("private socketpair traffic failed")
	}
	if err := unix.Connect(pair[0], &unix.SockaddrUnix{Name: filepath.Join(base, "output", "host.sock")}); err != unix.EISCONN {
		t.Fatal("stream socketpair acquired a host peer:", err)
	}
	if err := unix.Shutdown(pair[0], unix.SHUT_RDWR); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(pair[0], &unix.SockaddrUnix{Name: filepath.Join(base, "output", "host.sock")}); err != unix.EISCONN {
		t.Fatal("shutdown socketpair acquired a host peer:", err)
	}
	_ = unix.Close(pair[0])
	_ = unix.Close(pair[1])
	if pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0); err != unix.EPERM {
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
		t.Fatal("reconnectable datagram socketpair allowed:", err)
	}
	if os.Getenv("PROBE_TTY") == "1" {
		termios, err := unix.IoctlGetTermios(0, unix.TCGETS)
		if err != nil || unix.IoctlSetTermios(0, unix.TCSETS, termios) != nil {
			t.Fatal("inherited PTY termios denied")
		}
		winsize, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
		if err != nil || unix.IoctlSetWinsize(0, unix.TIOCSWINSZ, winsize) != nil {
			t.Fatal("inherited PTY window size denied")
		}
	}
	if address := os.Getenv("PROBE_TCP"); address != "" {
		conn, err := net.DialTimeout("tcp4", address, 2*time.Second)
		if err != nil {
			t.Fatal("outbound network positive control:", err)
		}
		_ = conn.Close()
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("UDP bind positive control:", err)
		}
		_ = udp.Close() // UDP reception is deliberately not denied by listen/accept.
		linuxProbeLoopback(t, address)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestLinuxSealDescendant$", "--", "acs-seal-descendant")
	child.Env = os.Environ()
	child.Stdin = os.Stdin
	if data, err := child.CombinedOutput(); err != nil {
		t.Fatalf("fork/exec inherited restriction probe: %v %s", err, data)
	}
}

func TestLinuxSealDescendant(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "acs-seal-descendant" {
		return
	}
	if _, err := os.ReadFile(filepath.Join(os.Getenv("PROBE_ROOT"), "host-canary")); err == nil {
		t.Fatal("descendant escaped Landlock")
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_LISTEN, ^uintptr(0), 0, 0); errno != unix.EPERM {
		t.Fatal("descendant escaped seccomp")
	}
	if err := linuxDial("127.0.0.1:9"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("descendant loopback connect: %v", err)
	}
}

func linuxDial(address string) error {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func linuxProbeLoopback(t *testing.T, remote string) {
	t.Helper()
	for _, address := range []string{"127.0.0.1:9", "127.0.0.2:9", "[::1]:9"} {
		if err := linuxDial(address); !errors.Is(err, unix.EPERM) {
			t.Fatalf("connect %s: %v", address, err)
		}
	}
	if errno := linuxProbeMappedLoopback(9); errno != unix.EPERM {
		t.Fatalf("v4-mapped loopback: %v", errno)
	}
	if errno := linuxProbeUDP("127.0.0.1", 9); errno != unix.EPERM {
		t.Fatalf("udp loopback sendto: %v", errno)
	}
	if os.Getenv("PROBE_LOCALHOST") == "1" {
		if err := linuxDial("localhost:9"); !errors.Is(err, unix.EPERM) {
			t.Fatalf("localhost: %v", err)
		}
	}
	if _, err := net.Listen("tcp4", "127.0.0.1:0"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("loopback listen: %v", err)
	}
	_, port, err := net.SplitHostPort(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := linuxDial(net.JoinHostPort("127.0.0.1", port)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("loopback on open remote port: %v", err)
	}
	host, _, _ := net.SplitHostPort(remote)
	if errno := linuxProbeSendmsg(host, port); errno == unix.EPERM {
		t.Fatal("sendmsg to a non-loopback address was denied")
	}
	if errno, n := linuxProbeSendmmsg("127.0.0.1", 9); errno != unix.EPERM || n != 0 {
		t.Fatalf("sendmmsg loopback: %v len %d", errno, n)
	}
	if errno, n := linuxProbeSendmmsg(host, linuxPort(port)); errno == unix.EPERM || (errno == 0 && n != 1) {
		t.Fatalf("sendmmsg non-loopback: %v len %d", errno, n)
	}
	if resolver := os.Getenv("PROBE_RESOLVER"); resolver != "" {
		if errno := linuxProbeUDP(resolver, 53); errno == unix.EPERM {
			t.Fatalf("resolver %s:53 denied", resolver)
		}
		if resolver != "127.0.0.53" && linuxProbeUDP("127.0.0.53", 53) != unix.EPERM {
			t.Fatal("unlisted loopback resolver was allowed")
		}
	}
	if allow := os.Getenv("PROBE_LOOPBACK_ALLOW"); allow != "" {
		if err := linuxDial(allow); err != nil {
			t.Fatalf("selected loopback port: %v", err)
		}
		_, allowPort, err := net.SplitHostPort(allow)
		if err != nil {
			t.Fatal(err)
		}
		if err := linuxDial(net.JoinHostPort("127.0.0.2", allowPort)); errors.Is(err, unix.EPERM) {
			t.Fatalf("127.0.0.2 selected port: %v", err)
		}
		if err := linuxDial(net.JoinHostPort("::1", allowPort)); errors.Is(err, unix.EPERM) {
			t.Fatalf("::1 selected port: %v", err)
		}
		if errno := linuxProbeMappedLoopback(linuxPort(allowPort)); errno == unix.EPERM {
			t.Fatal("v4-mapped selected port was denied")
		}
	}
}

func linuxPort(port string) int {
	n := 0
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	return n
}

func linuxProbeMappedLoopback(port int) unix.Errno {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unix.EPERM
	}
	defer unix.Close(fd)
	var raw [28]byte
	raw[0] = unix.AF_INET6
	raw[2] = byte(port >> 8)
	raw[3] = byte(port)
	raw[18], raw[19], raw[20], raw[23] = 0xff, 0xff, 127, 1
	_, _, errno := unix.RawSyscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&raw[0])), 28)
	return errno
}

func linuxIPv4Sockaddr(ip string, port int) ([16]byte, unix.Errno) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return [16]byte{}, unix.EINVAL
	}
	var raw [16]byte
	raw[0] = unix.AF_INET
	raw[2] = byte(port >> 8)
	raw[3] = byte(port)
	copy(raw[4:8], parsed)
	return raw, 0
}

func linuxProbeUDP(ip string, port int) unix.Errno {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unix.EPERM
	}
	defer unix.Close(fd)
	raw, errno := linuxIPv4Sockaddr(ip, port)
	if errno != 0 {
		return errno
	}
	payload := [1]byte{'x'}
	_, _, errno = unix.RawSyscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&payload[0])), 1, 0, uintptr(unsafe.Pointer(&raw[0])), 16)
	return errno
}

func linuxProbeSendmmsg(ip string, port int) (unix.Errno, uint32) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unix.EPERM, 0
	}
	defer unix.Close(fd)
	raw, errno := linuxIPv4Sockaddr(ip, port)
	if errno != 0 {
		return errno, 0
	}
	payload := [1]byte{'x'}
	iov := unix.Iovec{Base: &payload[0], Len: 1}
	msg := unix.Mmsghdr{Hdr: unix.Msghdr{Name: &raw[0], Namelen: 16, Iov: &iov, Iovlen: 1}}
	_, _, errno = unix.RawSyscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), 1, 0, 0, 0)
	runtime.KeepAlive(&payload)
	runtime.KeepAlive(&raw)
	return errno, msg.Len
}

func linuxProbeSendmsg(ip, port string) unix.Errno {
	n := linuxPort(port)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unix.EPERM
	}
	defer unix.Close(fd)
	raw, errno := linuxIPv4Sockaddr(ip, n)
	if errno != 0 {
		return errno
	}
	payload := [1]byte{'x'}
	iov := unix.Iovec{Base: &payload[0], Len: 1}
	hdr := unix.Msghdr{Name: &raw[0], Namelen: 16, Iov: &iov, Iovlen: 1}
	_, _, errno = unix.RawSyscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&hdr)), 0)
	return errno
}

func linuxNativeIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		return ip.String()
	}
	t.Fatal("no non-loopback IPv4 address")
	return ""
}

func linuxProbeResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1]
		}
	}
	return ""
}

type linuxNativeFixture struct {
	base string
	plan linuxFilesystemPlan
	wire linuxLaunchWire
	env  map[string]string
}

func linuxNewNativeFixture(t *testing.T, compile bool) linuxNativeFixture {
	t.Helper()
	base := t.TempDir()
	for _, path := range []string{"work", "output", "bin", "state/sessions/one/home", "state/sessions/one/tmp"} {
		if err := os.MkdirAll(filepath.Join(base, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{"work/allowed": "allowed", "host-canary": "private"} {
		if err := os.WriteFile(filepath.Join(base, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(base, "bin", "probe")
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil || os.WriteFile(executable, self, 0700) != nil {
		t.Fatal("copy static probe")
	}
	w := linuxLaunchWire{Version: 1, Executable: executable,
		Argv: []string{executable, "-test.run=^TestLinuxSealProbe$", "--", "acs-seal-probe"},
		Home: filepath.Join(base, "state/sessions/one/home"), Temporary: filepath.Join(base, "state/sessions/one/tmp"), Directory: filepath.Join(base, "work")}
	if !compile {
		// Primitive tests exercise kernel enforcement independently of the
		// compiler's supported host filesystem subset (e.g. overlay st_dev).
		w.Rules = []linuxWireRule{{w.Directory, linuxReadTree}, {executable, linuxReadFile},
			{filepath.Join(base, "output"), linuxReadTree | linuxWriteTree},
			{w.Home, linuxReadTree | linuxWriteTree}, {w.Temporary, linuxReadTree | linuxWriteTree},
			{"/etc/hosts", linuxReadFile}}
		return linuxNativeFixture{base: base, wire: w}
	}
	tree := linuxFilesystemSnapshot{}
	// Complete capture of a private, test-owned tree. Production snapshot/race
	// policy remains separate from this deliberately small test fixture.
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var x unix.Statx_t
		var fs unix.Statfs_t
		if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &x) != nil || unix.Statfs(path, &fs) != nil {
			return errLinuxSeal
		}
		node := linuxFilesystemNode{identity: identityFromFileInfo(info, info.Sys().(*syscall.Stat_t)), mountID: x.Mnt_id, filesystemType: fs.Type}
		if entry.IsDir() {
			children, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			for _, child := range children {
				node.children = append(node.children, child.Name())
			}
		}
		tree[path] = node
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := validatedProcessRequest{workspace: filepath.Join(base, "work"), workspaceAccess: WorkspaceAccessReadOnly,
		sessionsDirectory: filepath.Join(base, "state/sessions"), sessionDirectory: filepath.Join(base, "state/sessions/one"),
		sessionHome: filepath.Join(base, "state/sessions/one/home"), temporaryDirectory: filepath.Join(base, "state/sessions/one/tmp"),
		executable: executable, runtimeAuthority: linuxFilesystemRuntimeAuthority()}
	output := filepath.Join(base, "output")
	r.filesystemGrants = []FilesystemGrant{{path: output, logicalPath: output, identity: tree[output].identity,
		Access: PathAccessReadWrite, Type: PathTypeDirectory, effective: true}}
	plan, err := compileLinuxFilesystemPlan(r, tree, linuxFilesystemFeatures{6, linuxUnixSocketsDenyCreation}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range plan.rules {
		w.Rules = append(w.Rules, linuxWireRule{rule.path, rule.access})
	}
	return linuxNativeFixture{base: base, plan: plan, wire: w}
}

func linuxRunNativeFixture(t *testing.T, f linuxNativeFixture, mode string, composed, terminal bool, start byte) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	values := map[string]string{"SELECTED": "synthetic-secret", "PROBE_ROOT": f.base}
	if terminal {
		values["PROBE_TTY"] = "1"
	}
	hostIP := linuxNativeIPv4(t)
	listener, err := net.Listen("tcp4", hostIP+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	values["PROBE_TCP"] = listener.Addr().String()
	if resolver := linuxProbeResolver(); resolver != "" {
		values["PROBE_RESOLVER"] = resolver
	}
	if !composed {
		values["PROBE_LOCALHOST"] = "1"
	}
	for key, value := range f.env {
		values[key] = value
	}
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	lease := linuxTestLease(t, values)
	transport, err := linuxWriteTransport(f.wire, lease)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "-malformed-transport" {
		_ = transport.Close()
		transport, err = linuxSealedMemfd([]byte("invalid"))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer transport.Close()
	statusRead, statusWrite, _ := os.Pipe()
	gateRead, gateWrite, _ := os.Pipe()
	for _, file := range []*os.File{statusRead, statusWrite, gateRead, gateWrite} {
		defer file.Close()
	}
	input, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if terminal {
		master, slave, err := pty.Open()
		if err != nil {
			linuxNativeUnavailable(t, "PTY allocation")
		}
		defer master.Close()
		defer slave.Close()
		input = slave
	}
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxSealHelper$", "--", "acs-seal-helper"+mode)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, output
	cmd.ExtraFiles = []*os.File{transport, statusWrite, gateRead}
	if composed {
		helper, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer helper.Close()
		prepared, err := linuxPrepareBwrap(ctx, f.plan, f.wire, lease, helper, statusWrite, gateRead,
			[3]*os.File{input, output, output}, cmd.Args[1:])
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		cmd = prepared.command
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: linuxNativeCgroup(t)}
	}
	// Insert a real host socket after source validation; a scan alone cannot
	// protect a live writable grant from this race.
	hostSocket, err := net.Listen("unix", filepath.Join(f.base, "output", "host.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer hostSocket.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = statusWrite.Close()
	_ = gateRead.Close()
	_ = statusRead.SetReadDeadline(time.Now().Add(5 * time.Second))
	var receipt [1]byte
	n, readErr := statusRead.Read(receipt[:])
	if n == 1 && receipt[0] == 'R' {
		if start != 0 {
			_, _ = gateWrite.Write([]byte{start})
		}
		_ = gateWrite.Close()
		if start == 'S' {
			// EOF confirms successful exec closed the status descriptor.
			n, readErr = statusRead.Read(receipt[:])
			if n != 0 || readErr != io.EOF {
				_ = cmd.Process.Kill()
			}
		}
	} else if mode == "" && start == 'S' {
		_ = cmd.Process.Kill()
	}
	var boundaryErr error
	if n == 1 && receipt[0] == 'E' {
		boundaryErr = linuxReadRestrictedFailure(statusRead)
	}
	waitErr := cmd.Wait()
	_, _ = output.Seek(0, io.SeekStart)
	data, _ := io.ReadAll(io.LimitReader(output, 16384))
	if mode == "" && start == 'S' && (n != 0 || readErr != io.EOF) {
		t.Fatalf("missing sealed/exec receipt: n=%d err=%v output=%s", n, readErr, data)
	}
	return string(data), errors.Join(waitErr, boundaryErr)
}

func TestLinuxNativeRestrictionControls(t *testing.T) {
	linuxNativePrerequisites(t)
	// This is a primitive test, with no Session and no namespace claim. Only a
	// fixed test probe runs; the composed test below additionally requires bwrap
	// and delegation. The baseline makes listen denial distinguishable from EBADF.
	if _, _, errno := unix.RawSyscall(unix.SYS_LISTEN, ^uintptr(0), 0, 0); errno != unix.EBADF {
		linuxNativeUnavailable(t, "unfiltered listen baseline")
	}
	t.Setenv("UNSELECTED_SECRET", "ambient-secret")
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
			f := linuxNewNativeFixture(t, false)
			data, err := linuxRunNativeFixture(t, f, "", false, terminal, 'S')
			if err != nil {
				t.Fatalf("restricted probe: %v %s", err, data)
			}
		})
	}
}

func TestLinuxNativeSetupFailuresNeverExec(t *testing.T) {
	linuxNativePrerequisites(t)
	for _, mode := range []string{"-bad-landlock", "-bad-seccomp", "-deny-prctl", "-deny-capset", "-deny-close-range", "-deny-dup3",
		"-malformed-transport", "gate-eof", "gate-wrong", "missing-exec", "missing-rule"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxNewNativeFixture(t, false)
			start, helperMode := byte('S'), ""
			switch mode {
			case "-bad-landlock", "-bad-seccomp", "-deny-prctl", "-deny-capset", "-deny-close-range", "-deny-dup3", "-malformed-transport":
				helperMode = mode
			case "gate-eof":
				start = 0
			case "gate-wrong":
				start = 'X'
			case "missing-exec":
				// Keep Landlock setup valid, but make the final exec path absent.
				f.wire.Executable += "-missing"
				f.wire.Argv[0] = f.wire.Executable
				helperMode = "-missing-exec"
			case "missing-rule":
				f.wire.Rules[0].Path += "-missing"
				helperMode = "-missing-rule"
			}
			data, err := linuxRunNativeFixture(t, f, helperMode, false, false, start)
			if err == nil {
				t.Fatalf("setup failure succeeded: %s", data)
			}
			if step := map[string]string{
				"-bad-landlock": "landlock_restrict_self", "-bad-seccomp": "seccomp",
				"-deny-prctl": "PR_SET_NO_NEW_PRIVS", "-deny-capset": "capset",
				"-deny-close-range": "close_range", "-deny-dup3": "dup3 status",
			}[mode]; step != "" && !strings.Contains(err.Error(), "restricted child: "+step) {
				t.Fatalf("setup failure lost its syscall stage: %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.base, "output", "started")); !os.IsNotExist(err) {
				t.Fatal("untrusted target started during failed setup")
			}
		})
	}
}

func TestLinuxNativeBwrapComposition(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, check := range report.Checks {
			if check.Status != "pass" {
				missing = append(missing, check.ID+":"+check.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	f := linuxNewNativeFixture(t, true)
	if data, err := linuxRunNativeFixture(t, f, "", true, true, 'S'); err != nil {
		t.Fatalf("composed native probe: %v %s", err, data)
	}
}

func TestLinuxNativeLoopbackExceptions(t *testing.T) {
	linuxNativePrerequisites(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	for _, composed := range []bool{false, true} {
		t.Run(fmt.Sprintf("composed=%t", composed), func(t *testing.T) {
			if composed {
				linuxRequireComposed(t)
			}
			f := linuxNewNativeFixture(t, composed)
			f.wire.LoopbackPorts = []int{ln.Addr().(*net.TCPAddr).Port}
			f.env = map[string]string{"PROBE_LOOPBACK_ALLOW": ln.Addr().String()}
			if data, err := linuxRunNativeFixture(t, f, "", composed, false, 'S'); err != nil {
				t.Fatalf("selected loopback port: %v %s", err, data)
			}
		})
	}
}

func TestLinuxNativeCodexCallback(t *testing.T) {
	linuxNativePrerequisites(t)
	held, err := net.Listen("tcp4", "127.0.0.1:1455")
	if err != nil {
		t.Fatal(err)
	}
	_ = held.Close()
	for _, composed := range []bool{false, true} {
		t.Run(fmt.Sprintf("composed=%t", composed), func(t *testing.T) {
			if composed {
				linuxRequireComposed(t)
			}
			f := linuxNewNativeFixture(t, composed)
			f.wire.LoopbackPorts = []int{linuxCodexCallbackPort}
			f.wire.LoopbackCallback = true
			f.wire.Argv = []string{f.wire.Executable, "-test.run=^TestLinuxLoopbackCallbackProbe$", "--", "acs-loopback-callback"}
			if data, err := linuxRunNativeFixture(t, f, "", composed, false, 'S'); err != nil {
				t.Fatalf("codex callback: %v %s", err, data)
			}
		})
	}
}

func TestLinuxLoopbackCallbackProbe(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "acs-loopback-callback" {
		return
	}
	// Denied binds run before the successful listens so port 1455 is free.
	// Rebinding it after an accepted connection races with socket close.
	for _, address := range []string{"127.0.0.2:1455", "127.0.0.1:1456", "0.0.0.0:1455"} {
		if _, err := net.Listen("tcp4", address); !errors.Is(err, unix.EPERM) {
			t.Fatalf("listen %s: %v", address, err)
		}
	}
	if _, err := net.Listen("tcp6", "[::]:1455"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("wildcard ipv6 listen: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:1455")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	errCh := make(chan error, 1)
	go func() {
		conn, err := net.DialTimeout("tcp4", "127.0.0.1:1455", time.Second)
		if err != nil {
			errCh <- err
			return
		}
		_, err = conn.Write([]byte("ok"))
		_ = conn.Close()
		errCh <- err
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("callback payload: %v %q", err, buf)
	}
	_ = conn.Close()
	_ = ln.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	ln6, err := net.Listen("tcp6", "[::1]:1455")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln6.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		conn, err := net.DialTimeout("tcp6", "[::1]:1455", time.Second)
		if err == nil {
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()
	conn, err = ln6.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("ipv6 callback: %v %q", err, buf)
	}
	_ = conn.Close()
	_ = ln6.Close()
}

func linuxRequireComposed(t *testing.T) {
	t.Helper()
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, check := range report.Checks {
			if check.Status != "pass" {
				missing = append(missing, check.ID+":"+check.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
}

// Test-only cgroup ownership: every composed launch enters atomically via
// CLONE_INTO_CGROUP. Cleanup requires kernel empty evidence and pinned identity.
func linuxNativeCgroup(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(data), "0::/") || strings.Count(string(data), "\n") != 1 {
		t.Fatal("unexpected delegated cgroup metadata")
	}
	relative := strings.TrimSpace(strings.TrimPrefix(string(data), "0::/"))
	root, err := unix.Open("/sys/fs/cgroup", unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	if relative == "" {
		relative = "."
	}
	parent, err := unix.Openat2(root, relative, &unix.OpenHow{Flags: unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if unix.Fstat(parent, &stat) != nil || stat.Uid != uint32(os.Getuid()) || stat.Mode&0022 != 0 {
		_ = unix.Close(parent)
		t.Fatal("delegation identity changed")
	}
	name := "acs-seal-test-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if unix.Mkdirat(parent, name, 0700) != nil {
		_ = unix.Close(parent)
		t.Fatal("create delegated test cgroup")
	}
	child, err := unix.Openat(parent, name, unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		_ = unix.Close(parent)
		t.Fatal(err)
	}
	var identity unix.Stat_t
	if unix.Fstat(child, &identity) != nil {
		_ = unix.Close(child)
		_ = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		_ = unix.Close(parent)
		t.Fatal("test cgroup identity unavailable")
	}
	t.Cleanup(func() {
		defer unix.Close(parent)
		defer unix.Close(child)
		writeFD, err := unix.Openat(child, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal("test cgroup cleanup unproven")
		}
		_, err = unix.Write(writeFD, []byte("1"))
		_ = unix.Close(writeFD)
		if err != nil {
			t.Fatal("test cgroup kill failed; cleanup unproven")
		}
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			fd, err := unix.Openat(child, "cgroup.events", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				break
			}
			f := os.NewFile(uintptr(fd), "events")
			events, err := io.ReadAll(io.LimitReader(f, 4096))
			_ = f.Close()
			if err == nil && bytes.Contains(events, []byte("populated 0\n")) {
				var current unix.Stat_t
				if unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Ino != identity.Ino || current.Dev != identity.Dev {
					t.Fatal("test cgroup identity changed; cleanup unproven")
				}
				if unix.Unlinkat(parent, name, unix.AT_REMOVEDIR) == nil {
					return
				}
			}
		}
		t.Fatal("test cgroup settlement unproven; cgroup retained")
	})
	return child
}

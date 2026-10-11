package linuxprobe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const helperArgument = "--acs-internal-linux-capability-probe"
const helperReceipt = "acs-linux-probe-v1\n"

var errProbe = errors.New("Linux capability probe failed")

func init() {
	if len(os.Args) < 2 || os.Args[1] != helperArgument {
		return
	}
	// A fixed private grammar: no executable, path, environment value, policy or
	// user command can be supplied to this helper.
	if len(os.Args) != 3 {
		os.Exit(125)
	}
	ok := false
	switch os.Args[2] {
	case "userns":
		ok = namespaceControl() == nil
	case "seccomp":
		ok = seccompControl() == nil
	case "cgroup":
		_, _ = io.WriteString(os.Stdout, helperReceipt)
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(125) // Only cgroup.kill is an accepted end to this control.
	}
	if !ok {
		os.Exit(125)
	}
	_, _ = io.WriteString(os.Stdout, helperReceipt)
	os.Exit(0)
}

func helperCommand(ctx context.Context, mode string) *exec.Cmd {
	// Re-exec the running inode, not argv[0], PATH, or a user-selected helper.
	cmd := exec.CommandContext(ctx, "/proc/self/exe", helperArgument, mode)
	cmd.Dir = "/"
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	return cmd
}

func runHelper(ctx context.Context, mode string, attr *syscall.SysProcAttr) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, mode)
	cmd.SysProcAttr = attr
	output := &receiptWriter{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil || !bytes.Equal(output.data, []byte(helperReceipt)) {
		return errProbe
	}
	return nil
}

// Bound helper output even if the re-executed binary fails unexpectedly.
type receiptWriter struct{ data []byte }

func (w *receiptWriter) Write(p []byte) (int, error) {
	if len(w.data)+len(p) > len(helperReceipt) {
		return 0, errProbe
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

func probeUserNamespaces(ctx context.Context) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return errProbe
	}
	return runHelper(ctx, "userns", &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	})
}

func namespaceControl() error {
	if os.Getpid() != 1 || os.Getuid() != 0 {
		return errProbe
	}
	// A mount operation in the private namespace verifies more than a sysctl
	// or successful userns creation (notably under AppArmor). No host mount is
	// altered and the namespace vanishes with this single helper.
	return unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
}

func probeSeccomp(ctx context.Context) error { return runHelper(ctx, "seccomp", nil) }

func seccompControl() error {
	if runtime.GOARCH != "amd64" {
		return errProbe
	}
	runtime.LockOSThread()
	// Irreversible restrictions are installed only in this disposable helper.
	if _, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0); errno != 0 {
		return errProbe
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_GETPPID, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return errProbe
	}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 || result != 0 {
		return errProbe
	}
	_, _, denied := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	pid, _, allowed := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	if denied != unix.EACCES || allowed != 0 || pid == 0 {
		return errProbe
	}
	return nil
}

package launch

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// All memory, strings, file descriptors and kernel policy are prepared before
// fork. The child must never execute Go (including the runtime's signal handlers)
// between fork and exec. See restrict_linux_amd64.s for the complete boundary.
type linuxExecBoundary struct {
	ruleset  int64
	status   int64
	gate     int64
	program  *unix.SockFprog
	path     *byte
	argv     **byte
	env      **byte
	terminal int64 // -1 or a private slave duplicated above all protocol FDs
	notify   int64 // socket that receives the seccomp listener; must be > 2
}

//go:noescape
func linuxForkExec(config *linuxExecBoundary) (pid uintptr, errno unix.Errno)

func linuxLandlockRuleset(rules []linuxLandlockRule) (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 6 {
		var cause error
		if errno != 0 {
			cause = errno
		}
		return -1, linuxStepError(errLinuxSeal, "query Landlock ABI (requires >=6)", cause)
	}
	attr := unix.LandlockRulesetAttr{Handled_access_fs: linuxHandledFilesystem,
		Scoped: unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL}
	// Only pass the ABI 6 prefix through Scoped. Newer x/sys structs also
	// contain quiet fields, which this policy neither enables nor requires.
	attrSize := unsafe.Offsetof(attr.Scoped) + unsafe.Sizeof(attr.Scoped)
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), attrSize, 0)
	if errno != 0 {
		return -1, linuxStepError(errLinuxSeal, "landlock_create_ruleset", errno)
	}
	ok := false
	defer func() {
		if !ok {
			_ = unix.Close(int(fd))
		}
	}()
	for i, rule := range rules {
		if !linuxCanonicalPlanPath(rule.path) || rule.access == 0 || rule.access & ^uint64(linuxHandledFilesystem) != 0 {
			return -1, errLinuxSeal
		}
		pathFD, err := unix.Openat2(unix.AT_FDCWD, rule.path, &unix.OpenHow{
			Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return -1, linuxStepError(errLinuxSeal, fmt.Sprintf("open Landlock rule %d (%s)", i, rule.path), err)
		}
		pathAttr := unix.LandlockPathBeneathAttr{Allowed_access: rule.access, Parent_fd: int32(pathFD)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&pathAttr)), 0, 0, 0)
		_ = unix.Close(pathFD)
		if errno != 0 {
			return -1, linuxStepError(errLinuxSeal, fmt.Sprintf("landlock_add_rule %d (%s)", i, rule.path), errno)
		}
	}
	ok = true
	return int(fd), nil
}

func linuxExecStrings(values []string) ([]*byte, error) {
	result := make([]*byte, len(values)+1)
	for i, value := range values {
		if strings.ContainsRune(value, 0) {
			return nil, errLinuxSeal
		}
		var err error
		result[i], err = unix.BytePtrFromString(value)
		if err != nil {
			return nil, errLinuxSeal
		}
	}
	return result, nil
}

// Called only by the test harness at present. It deliberately returns a PID,
// not a Process/Session or cleanup proof. Containment integration is separate.
func linuxStartRestricted(rules []linuxLandlockRule, path string, args, env []string, status, gate int) (int, error) {
	return linuxStartRestrictedTerminal(rules, path, args, env, status, gate, -1, linuxLoopbackPolicy{})
}

func linuxStartRestrictedTerminal(rules []linuxLandlockRule, path string, args, env []string, status, gate, terminal int, policy linuxLoopbackPolicy) (int, error) {
	if !linuxCanonicalPlanPath(path) || len(args) == 0 || args[0] != path || status < 3 || gate < 3 || status == gate {
		return -1, errLinuxSeal
	}
	for fd := 0; fd < 3; fd++ {
		if err := linuxCheckStdio(fd); err != nil {
			return -1, err
		}
	}
	argv, err := linuxExecStrings(args)
	if err != nil {
		return -1, err
	}
	envp, err := linuxExecStrings(env)
	if err != nil {
		return -1, err
	}
	ruleset, err := linuxLandlockRuleset(rules)
	if err != nil {
		return -1, err
	}
	rulesetCopy, err := unix.FcntlInt(uintptr(ruleset), unix.F_DUPFD_CLOEXEC, 128)
	_ = unix.Close(ruleset)
	if err != nil {
		return -1, linuxStepError(errLinuxSeal, "duplicate Landlock ruleset", err)
	}
	ruleset = rulesetCopy
	defer unix.Close(ruleset)
	// Reserve disjoint copies before the child remaps status/gate onto 3/4.
	statusCopy, err := unix.FcntlInt(uintptr(status), unix.F_DUPFD_CLOEXEC, 128)
	if err != nil {
		return -1, linuxStepError(errLinuxSeal, "duplicate restricted status pipe", err)
	}
	defer unix.Close(statusCopy)
	gateCopy, err := unix.FcntlInt(uintptr(gate), unix.F_DUPFD_CLOEXEC, 128)
	if err != nil {
		return -1, linuxStepError(errLinuxSeal, "duplicate restricted start pipe", err)
	}
	defer unix.Close(gateCopy)
	terminalCopy := -1
	if terminal >= 0 {
		terminalCopy, err = unix.FcntlInt(uintptr(terminal), unix.F_DUPFD_CLOEXEC, 128)
		if err != nil {
			return -1, linuxStepError(errLinuxSeal, "duplicate private terminal", err)
		}
		defer unix.Close(terminalCopy)
	}
	if err := linuxLoopbackNotifSizes(); err != nil {
		return -1, err
	}
	// The child installs its notification filter and only then can create the
	// listener. Sending that fd with sendmsg would block on the filter itself,
	// so the child publishes a byte and this process steals the known fd.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, linuxStepError(errLinuxSeal, "create loopback handshake socket", err)
	}
	handshake := os.NewFile(uintptr(pair[0]), "loopback-handshake")
	closeHandshake := func() {
		if handshake != nil {
			_ = handshake.Close()
			handshake = nil
		}
	}
	defer closeHandshake()
	notifyCopy, err := unix.FcntlInt(uintptr(pair[1]), unix.F_DUPFD_CLOEXEC, 128)
	_ = unix.Close(pair[1])
	if err != nil {
		return -1, linuxStepError(errLinuxSeal, "duplicate loopback handshake socket", err)
	}
	defer unix.Close(notifyCopy)
	filter := linuxSeccompFilter(policy.Callback)
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	config := linuxExecBoundary{int64(ruleset), int64(statusCopy), int64(gateCopy), &program, argv[0], &argv[0], &envp[0], int64(terminalCopy), int64(notifyCopy)}
	runtime.LockOSThread()
	pid, errno := linuxForkExec(&config)
	runtime.UnlockOSThread()
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envp)
	runtime.KeepAlive(filter)
	if errno != 0 {
		return -1, linuxStepError(errLinuxSeal, "fork restricted child", errno)
	}
	listener, err := linuxHandoffListener(int(pid), int(handshake.Fd()))
	closeHandshake()
	if err != nil {
		if pidfd, openErr := unix.PidfdOpen(int(pid), 0); openErr == nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			_ = unix.Close(pidfd)
		}
		var status unix.WaitStatus
		_, _ = unix.Wait4(int(pid), &status, 0, nil)
		return -1, linuxStepError(errLinuxSeal, "receive loopback listener", err)
	}
	go linuxServeNotifications(listener, policy)
	return int(pid), nil
}

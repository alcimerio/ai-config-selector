package launch

import "golang.org/x/sys/unix"

// linuxSeccompFilter is installed only after trusted namespace setup. Keep this
// policy independent of the host's available syscalls: an ENOSYS fallback is
// intentional for clone3 (whose flags are indirect), never for a security gate.
func linuxSeccompFilter() []unix.SockFilter {
	return linuxSeccompFilterForSetup(false)
}

// Only the trusted helper's setup filter can acquire an unused private tty.
// Every untrusted child always installs linuxSeccompFilter(), which denies it.
func linuxSeccompFilterForSetup(privateTerminal bool) []unix.SockFilter {
	const (
		load = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
		deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	)
	f := []unix.SockFilter{
		{Code: load, K: 4}, // seccomp_data.arch
		{Code: jeq, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load}, // seccomp_data.nr
		// x32 uses the same audit architecture and a different syscall table.
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	for _, nr := range []uint32{
		unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
		unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
		unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_MKNOD, unix.SYS_MKNODAT, unix.SYS_USERFAULTFD, unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_VHANGUP,
	} {
		f = append(f, unix.SockFilter{Code: jeq, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: deny})
	}
	f = append(f, unix.SockFilter{Code: jeq, K: unix.SYS_CLONE3, Jf: 1},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)})
	// Conditional blocks always return; skipping them leaves nr in the accumulator.
	block := func(nr uint32, body []unix.SockFilter) {
		f = append(f, unix.SockFilter{Code: jeq, K: nr, Jf: uint8(len(body))})
		f = append(f, body...)
	}
	block(unix.SYS_CLONE, []unix.SockFilter{
		{Code: load, K: 16}, // args[0], low word (all namespace flags are here)
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K,
			K: unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWNET |
				unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME, Jf: 1},
		{Code: ret, K: deny}, {Code: ret, K: unix.SECCOMP_RET_ALLOW},
	})
	block(unix.SYS_SOCKET, []unix.SockFilter{
		{Code: load, K: 16},
		{Code: jeq, K: unix.AF_INET, Jt: 2}, {Code: jeq, K: unix.AF_INET6, Jt: 1},
		{Code: ret, K: deny}, {Code: ret, K: unix.SECCOMP_RET_ALLOW},
	})
	block(unix.SYS_SOCKETPAIR, []unix.SockFilter{
		{Code: load, K: 16}, {Code: jeq, K: unix.AF_UNIX, Jt: 1},
		{Code: ret, K: deny},
		// Datagram pairs can reconnect/sendto arbitrary host pathname sockets.
		// A connected stream pair cannot acquire a new peer, even after shutdown.
		{Code: load, K: 24},
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: ^uint32(unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK)},
		{Code: jeq, K: unix.SOCK_STREAM, Jt: 1},
		{Code: ret, K: deny}, {Code: ret, K: unix.SECCOMP_RET_ALLOW},
	})
	// An allowlist also excludes terminal detachment, console redirection and
	// line-discipline changes. Compare the low word, as the kernel does for ioctl.
	ioctls := []unix.SockFilter{{Code: load, K: 24}}
	if privateTerminal {
		attach := []unix.SockFilter{
			{Code: load, K: 32}, {Code: jeq, K: 0, Jt: 1}, {Code: ret, K: deny},
			{Code: load, K: 36}, {Code: jeq, K: 0, Jt: 1}, {Code: ret, K: deny},
			{Code: load, K: 20}, {Code: jeq, K: 0, Jt: 1}, {Code: ret, K: deny},
			{Code: load, K: 16}, {Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 128, Jt: 1},
			{Code: ret, K: deny}, {Code: ret, K: unix.SECCOMP_RET_ALLOW},
		}
		ioctls = append(ioctls, unix.SockFilter{Code: jeq, K: unix.TIOCSCTTY, Jf: uint8(len(attach))})
		ioctls = append(ioctls, attach...)
	}
	for _, request := range []uint32{
		unix.TCGETS, unix.TCSETS, unix.TCSETSW, unix.TCSETSF,
		unix.TCGETS2, unix.TCSETS2, unix.TCSETSW2, unix.TCSETSF2,
		unix.TIOCGWINSZ, unix.TIOCSWINSZ, unix.TIOCGPGRP, unix.TIOCSPGRP, unix.TIOCGSID,
		unix.TIOCGPTN, unix.TIOCSPTLCK, unix.TIOCGPTLCK, unix.TIOCGPTPEER,
		unix.TIOCINQ, 0x5421, 0x5452, 0x5451, 0x5450, // FIONBIO, FIOASYNC, FIOCLEX, FIONCLEX
		unix.TCFLSH, unix.TCXONC, unix.TCSBRK,
	} {
		ioctls = append(ioctls, unix.SockFilter{Code: jeq, K: request, Jf: 1},
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	}
	ioctls = append(ioctls, unix.SockFilter{Code: ret, K: deny})
	block(unix.SYS_IOCTL, ioctls)
	return append(f, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
}

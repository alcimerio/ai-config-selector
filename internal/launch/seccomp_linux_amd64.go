package launch

import "golang.org/x/sys/unix"

// linuxSeccompFilter is the target policy installed with a notification
// listener. callback permits the managed Codex localhost:1455 accept path;
// the broker still checks the bound address. Setup filters must not notify:
// Bubblewrap installs them without a listener.
func linuxSeccompFilter(callback bool) []unix.SockFilter {
	return linuxSeccompProgram(false, true, callback)
}

// Only the trusted helper's setup filter can acquire an unused private tty.
// It allows the network calls the target filter later mediates.
func linuxSeccompFilterForSetup(privateTerminal bool) []unix.SockFilter {
	return linuxSeccompProgram(privateTerminal, false, false)
}

func linuxSeccompProgram(privateTerminal, notify, callback bool) []unix.SockFilter {
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
	denied := []uint32{
		unix.SYS_PTRACE, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
		unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
		unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_MKNOD, unix.SYS_MKNODAT, unix.SYS_USERFAULTFD, unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_VHANGUP,
	}
	if notify && !callback {
		denied = append(denied, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4)
	}
	if notify {
		// A newer user-notification filter can CONTINUE over this one. The
		// target must not be able to install another seccomp policy, and must
		// not be able to read the supervisor's memory or steal its descriptors.
		// The trusted setup filter keeps these calls: it brokers loopback
		// decisions for the child it just forked.
		denied = append(denied, unix.SYS_SECCOMP, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD)
	}
	for _, nr := range denied {
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
	requests := []uint32{
		unix.TCGETS, unix.TCSETS, unix.TCSETSW, unix.TCSETSF,
		unix.TCGETS2, unix.TCSETS2, unix.TCSETSW2, unix.TCSETSF2,
		unix.TIOCGWINSZ, unix.TIOCSWINSZ, unix.TIOCGPGRP, unix.TIOCSPGRP, unix.TIOCGSID,
		unix.TIOCGPTN, unix.TIOCSPTLCK, unix.TIOCGPTLCK, unix.TIOCGPTPEER,
		unix.TIOCINQ, 0x5421, 0x5452, 0x5451, 0x5450, // FIONBIO, FIOASYNC, FIOCLEX, FIONCLEX
		unix.TCFLSH, unix.TCXONC, unix.TCSBRK,
	}
	if !notify {
		// The trusted helper brokers notifications. The target filter must not
		// be able to answer its own listener.
		requests = append(requests, unix.SECCOMP_IOCTL_NOTIF_RECV, unix.SECCOMP_IOCTL_NOTIF_SEND,
			unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unix.SECCOMP_IOCTL_NOTIF_ADDFD)
	}
	for _, request := range requests {
		ioctls = append(ioctls, unix.SockFilter{Code: jeq, K: request, Jf: 1},
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	}
	ioctls = append(ioctls, unix.SockFilter{Code: ret, K: deny})
	block(unix.SYS_IOCTL, ioctls)
	if notify {
		user := uint32(unix.SECCOMP_RET_USER_NOTIF)
		block(unix.SYS_PRCTL, []unix.SockFilter{
			{Code: load, K: 16},
			{Code: jeq, K: unix.PR_SET_SECCOMP, Jf: 1},
			{Code: ret, K: deny},
			{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		})
		for _, nr := range []uint32{unix.SYS_CONNECT, unix.SYS_SENDMSG, unix.SYS_SENDMMSG} {
			f = append(f, unix.SockFilter{Code: jeq, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: user})
		}
		if callback {
			for _, nr := range []uint32{unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4} {
				f = append(f, unix.SockFilter{Code: jeq, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: user})
			}
		}
		// sendto(fd, buf, len, flags, addr, addrlen). A NULL address is a
		// connected send and carries no new destination.
		block(unix.SYS_SENDTO, []unix.SockFilter{
			{Code: load, K: 48},
			{Code: jeq, K: 0, Jf: 2},
			{Code: load, K: 52},
			{Code: jeq, K: 0, Jt: 1},
			{Code: ret, K: user},
			{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		})
	}
	return append(f, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
}

package launch

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FDs the raw child keeps across close_range: 0-2 stdio, 3 status, 4 gate,
// 5 handshake. seccomp(NEW_LISTENER) therefore returns 6, which the parent
// duplicates before the child closes it. CONTINUE is never used: the broker
// emulates the syscall with the address it copied.
const (
	linuxLoopbackListenerFD = 6
	linuxCodexCallbackPort  = 1455
	linuxLoopbackMaxAddr    = 128
	linuxLoopbackMaxPayload = 64 << 10
	linuxLoopbackMaxIovec   = 16
	linuxLoopbackMaxMmsg    = 32
	linuxMsghdrBytes        = 56
	linuxIovecBytes         = 16
	linuxMmsghdrBytes       = 64
)

type linuxLoopbackPolicy struct {
	Ports     []int
	Callback  bool
	Resolvers []netip.Addr
}

type linuxSeccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type linuxSeccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  linuxSeccompData
}

type linuxSeccompResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type linuxSeccompAddFD struct {
	ID         uint64
	Flags      uint32
	SrcFD      uint32
	NewFD      uint32
	NewFDFlags uint32
}

func linuxLoopbackNotifSizes() error {
	var sizes struct {
		notif uint16
		resp  uint16
		data  uint16
	}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	var cause error
	if errno != 0 {
		cause = errno
	}
	if errno != 0 || sizes.notif != uint16(unsafe.Sizeof(linuxSeccompNotif{})) ||
		sizes.resp != uint16(unsafe.Sizeof(linuxSeccompResp{})) ||
		sizes.data != uint16(unsafe.Sizeof(linuxSeccompData{})) {
		return linuxStepError(errLinuxSeal, "seccomp notification sizes", cause)
	}
	return nil
}

// Blocks until the child has installed the listener, then duplicates it.
// The handshake socket is closed by the caller.
func linuxHandoffListener(pid, conn int) (int, error) {
	tv := unix.NsecToTimeval(linuxContainmentTimeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(conn, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(conn, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	var buf [1]byte
	for {
		n, err := unix.Read(conn, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != 1 || buf[0] != 'L' {
			return -1, errLinuxSeal
		}
		break
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pidfd)
	listener, err := unix.PidfdGetfd(pidfd, linuxLoopbackListenerFD, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(listener)
	if _, err := unix.Write(conn, []byte{'K'}); err != nil {
		_ = unix.Close(listener)
		return -1, err
	}
	return listener, nil
}

func linuxServeNotifications(listener int, policy linuxLoopbackPolicy) {
	defer unix.Close(listener)
	for {
		var req linuxSeccompNotif
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(&req)))
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return
		}
		go linuxLoopbackDispatch(listener, req, policy, policy.Resolvers)
	}
}

func linuxLoopbackDispatch(listener int, req linuxSeccompNotif, policy linuxLoopbackPolicy, resolvers []netip.Addr) {
	result, done := linuxLoopbackHandle(listener, req, policy, resolvers)
	if !done {
		resp := linuxSeccompResp{ID: req.ID, Val: result}
		_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&resp)))
	}
}

func linuxNotifAlive(listener int, id uint64) bool {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id)))
	return errno == 0
}

func linuxLoopbackHandle(listener int, req linuxSeccompNotif, policy linuxLoopbackPolicy, resolvers []netip.Addr) (int64, bool) {
	if !linuxNotifAlive(listener, req.ID) {
		return 0, true
	}
	pid := int(req.PID)
	fd := int(int32(req.Data.Args[0]))
	switch uint32(req.Data.Nr) {
	case unix.SYS_CONNECT:
		return linuxLoopbackConnect(pid, fd, req.Data.Args[1], req.Data.Args[2], policy, resolvers), false
	case unix.SYS_SENDTO:
		return linuxLoopbackSendto(pid, fd, req, policy, resolvers), false
	case unix.SYS_SENDMSG:
		return linuxLoopbackSendmsg(pid, fd, req.Data.Args[1], req.Data.Args[2], policy, resolvers), false
	case unix.SYS_SENDMMSG:
		return linuxLoopbackSendmmsg(pid, fd, req, policy, resolvers), false
	case unix.SYS_LISTEN:
		return linuxLoopbackListen(pid, fd, req.Data.Args[1], policy), false
	case unix.SYS_ACCEPT, unix.SYS_ACCEPT4:
		return linuxLoopbackAccept(listener, req, policy)
	default:
		return -int64(unix.EPERM), false
	}
}

func linuxDupSocket(pid, target int) (int, error) {
	// The notification pid is the triggering thread, which may not be the
	// thread-group leader. Opening it without PIDFD_THREAD returns EINVAL.
	pidfd, err := unix.PidfdOpen(pid, unix.PIDFD_THREAD)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, target, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

func linuxSyscallResult(r uintptr, errno unix.Errno) int64 {
	if errno != 0 {
		return -int64(errno)
	}
	return int64(r)
}

func linuxNegErrno(err error) int64 {
	if errno, ok := err.(unix.Errno); ok && errno != 0 {
		return -int64(errno)
	}
	return -int64(unix.EFAULT)
}

func linuxReadRemote(pid int, addr uintptr, n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	if addr == 0 || n < 0 {
		return nil, unix.EFAULT
	}
	buf := make([]byte, n)
	got, err := unix.ProcessVMReadv(pid, []unix.Iovec{{Base: &buf[0], Len: uint64(n)}}, []unix.RemoteIovec{{Base: addr, Len: n}}, 0)
	runtime.KeepAlive(buf)
	if err != nil || got != n {
		if err == nil {
			err = unix.EFAULT
		}
		return nil, err
	}
	return buf, nil
}

func linuxWriteRemote(pid int, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if addr == 0 {
		return unix.EFAULT
	}
	got, err := unix.ProcessVMWritev(pid, []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}}, []unix.RemoteIovec{{Base: addr, Len: len(data)}}, 0)
	runtime.KeepAlive(data)
	if err != nil || got != len(data) {
		if err == nil {
			return unix.EFAULT
		}
		return err
	}
	return nil
}

type linuxSockKind int

const (
	linuxSockInvalid linuxSockKind = iota
	linuxSockUnix
	linuxSockIP
)

type linuxSock struct {
	ip   netip.Addr
	port int
}

func linuxClassifySockaddr(b []byte) (linuxSock, linuxSockKind) {
	if len(b) < 2 {
		return linuxSock{}, linuxSockInvalid
	}
	switch binary.LittleEndian.Uint16(b[:2]) {
	case unix.AF_UNIX:
		return linuxSock{}, linuxSockUnix
	case unix.AF_INET:
		if len(b) < 8 {
			return linuxSock{}, linuxSockInvalid
		}
		return linuxSock{ip: netip.AddrFrom4(([4]byte)(b[4:8])), port: int(binary.BigEndian.Uint16(b[2:4]))}, linuxSockIP
	case unix.AF_INET6:
		if len(b) < 24 {
			return linuxSock{}, linuxSockInvalid
		}
		var addr [16]byte
		copy(addr[:], b[8:24])
		return linuxSock{ip: netip.AddrFrom16(addr), port: int(binary.BigEndian.Uint16(b[2:4]))}, linuxSockIP
	default:
		return linuxSock{}, linuxSockInvalid
	}
}

func linuxResolvers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return linuxParseResolvers(string(data))
}

func linuxResolverStrings() []string {
	addrs := linuxResolvers()
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}

func linuxWireResolvers(values []string) []netip.Addr {
	var out []netip.Addr
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func linuxParseResolvers(text string) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" || len(out) == 8 {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func linuxResolverMatch(ip netip.Addr, resolvers []netip.Addr) bool {
	ip = ip.Unmap()
	for _, resolver := range resolvers {
		if resolver.Unmap() == ip {
			return true
		}
	}
	return false
}

// A copied sockaddr is the only destination the emulated call will use.
// Loopback is denied unless the port was granted or it is an exact resolver
// on port 53. Non-loopback destinations stay open, including the same port.
func linuxLoopbackPermitted(policy linuxLoopbackPolicy, addr []byte, resolvers []netip.Addr) bool {
	if len(addr) == 0 {
		return true
	}
	sock, kind := linuxClassifySockaddr(addr)
	switch kind {
	case linuxSockUnix:
		return true
	case linuxSockIP:
		if !sock.ip.IsLoopback() {
			return true
		}
		if sock.port == 53 && linuxResolverMatch(sock.ip, resolvers) {
			return true
		}
		for _, port := range policy.Ports {
			if port == sock.port {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func linuxReadSockaddr(pid int, ptr, n uint64) ([]byte, error) {
	if n > linuxLoopbackMaxAddr {
		return nil, unix.EPERM
	}
	if n == 0 || ptr == 0 {
		return nil, unix.EFAULT
	}
	return linuxReadRemote(pid, uintptr(ptr), int(n))
}

func linuxLoopbackConnect(pid, target int, ptr, n uint64, policy linuxLoopbackPolicy, resolvers []netip.Addr) int64 {
	addr, err := linuxReadSockaddr(pid, ptr, n)
	if err != nil {
		return linuxNegErrno(err)
	}
	if !linuxLoopbackPermitted(policy, addr, resolvers) {
		return -int64(unix.EPERM)
	}
	fd, err := linuxDupSocket(pid, target)
	if err != nil {
		return linuxNegErrno(err)
	}
	defer unix.Close(fd)
	r, _, errno := unix.RawSyscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	runtime.KeepAlive(addr)
	return linuxSyscallResult(r, errno)
}

func linuxLoopbackSendto(pid, target int, req linuxSeccompNotif, policy linuxLoopbackPolicy, resolvers []netip.Addr) int64 {
	addr, err := linuxReadSockaddr(pid, req.Data.Args[4], req.Data.Args[5])
	if err != nil {
		return linuxNegErrno(err)
	}
	if !linuxLoopbackPermitted(policy, addr, resolvers) {
		return -int64(unix.EPERM)
	}
	payload, err := linuxReadPayload(pid, req.Data.Args[1], req.Data.Args[2])
	if err != nil {
		return linuxNegErrno(err)
	}
	fd, err := linuxDupSocket(pid, target)
	if err != nil {
		return linuxNegErrno(err)
	}
	defer unix.Close(fd)
	var buf uintptr
	if len(payload) > 0 {
		buf = uintptr(unsafe.Pointer(&payload[0]))
	}
	r, _, errno := unix.RawSyscall6(unix.SYS_SENDTO, uintptr(fd), buf, uintptr(len(payload)), uintptr(req.Data.Args[3]), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	runtime.KeepAlive(payload)
	runtime.KeepAlive(addr)
	return linuxSyscallResult(r, errno)
}

func linuxReadPayload(pid int, ptr, n uint64) ([]byte, error) {
	if n > linuxLoopbackMaxPayload {
		return nil, unix.EMSGSIZE
	}
	if n == 0 {
		return []byte{}, nil
	}
	return linuxReadRemote(pid, uintptr(ptr), int(n))
}

type linuxCopiedMsg struct {
	name    []byte
	payload []byte
}

func linuxReadMsg(pid int, hdr uintptr) (linuxCopiedMsg, error) {
	raw, err := linuxReadRemote(pid, hdr, linuxMsghdrBytes)
	if err != nil {
		return linuxCopiedMsg{}, err
	}
	name := binary.LittleEndian.Uint64(raw[0:8])
	namelen := binary.LittleEndian.Uint32(raw[8:12])
	iov := binary.LittleEndian.Uint64(raw[16:24])
	iovlen := binary.LittleEndian.Uint64(raw[24:32])
	controllen := binary.LittleEndian.Uint64(raw[40:48])
	if controllen != 0 || namelen > linuxLoopbackMaxAddr || iovlen > linuxLoopbackMaxIovec {
		return linuxCopiedMsg{}, unix.EPERM
	}
	msg := linuxCopiedMsg{}
	if namelen > 0 {
		if name == 0 {
			return linuxCopiedMsg{}, unix.EFAULT
		}
		msg.name, err = linuxReadRemote(pid, uintptr(name), int(namelen))
		if err != nil {
			return linuxCopiedMsg{}, err
		}
	}
	if iovlen > 0 {
		msg.payload, err = linuxCopyIOV(pid, uintptr(iov), int(iovlen))
		if err != nil {
			return linuxCopiedMsg{}, err
		}
	}
	return msg, nil
}

func linuxCopyIOV(pid int, iovAddr uintptr, n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	if iovAddr == 0 {
		return nil, unix.EFAULT
	}
	raw, err := linuxReadRemote(pid, iovAddr, n*linuxIovecBytes)
	if err != nil {
		return nil, err
	}
	type span struct {
		base uintptr
		n    int
	}
	spans := make([]span, n)
	total := 0
	for i := range spans {
		off := i * linuxIovecBytes
		length := binary.LittleEndian.Uint64(raw[off+8 : off+16])
		if length > linuxLoopbackMaxPayload || total > linuxLoopbackMaxPayload-int(length) {
			return nil, unix.EMSGSIZE
		}
		spans[i] = span{uintptr(binary.LittleEndian.Uint64(raw[off : off+8])), int(length)}
		total += int(length)
	}
	buf := make([]byte, 0, total)
	for _, s := range spans {
		if s.n == 0 {
			continue
		}
		part, err := linuxReadRemote(pid, s.base, s.n)
		if err != nil {
			return nil, err
		}
		buf = append(buf, part...)
	}
	return buf, nil
}

func linuxSendCopied(fd int, msg linuxCopiedMsg, flags uint64) int64 {
	var hdr unix.Msghdr
	var iov unix.Iovec
	if len(msg.payload) > 0 {
		iov = unix.Iovec{Base: &msg.payload[0], Len: uint64(len(msg.payload))}
		hdr.Iov = &iov
		hdr.Iovlen = 1
	}
	if len(msg.name) > 0 {
		hdr.Name = &msg.name[0]
		hdr.Namelen = uint32(len(msg.name))
	}
	r, _, errno := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&hdr)), uintptr(flags))
	runtime.KeepAlive(msg.payload)
	runtime.KeepAlive(msg.name)
	runtime.KeepAlive(&iov)
	return linuxSyscallResult(r, errno)
}

func linuxLoopbackSendmsg(pid, target int, hdr, flags uint64, policy linuxLoopbackPolicy, resolvers []netip.Addr) int64 {
	if hdr == 0 {
		return -int64(unix.EFAULT)
	}
	msg, err := linuxReadMsg(pid, uintptr(hdr))
	if err != nil {
		return linuxNegErrno(err)
	}
	if !linuxLoopbackPermitted(policy, msg.name, resolvers) {
		return -int64(unix.EPERM)
	}
	fd, err := linuxDupSocket(pid, target)
	if err != nil {
		return linuxNegErrno(err)
	}
	defer unix.Close(fd)
	return linuxSendCopied(fd, msg, flags)
}

func linuxLoopbackSendmmsg(pid, target int, req linuxSeccompNotif, policy linuxLoopbackPolicy, resolvers []netip.Addr) int64 {
	vlen := req.Data.Args[2]
	if vlen > linuxLoopbackMaxMmsg {
		return -int64(unix.EPERM)
	}
	if vlen == 0 {
		return 0
	}
	if req.Data.Args[1] == 0 {
		return -int64(unix.EFAULT)
	}
	msgs := make([]linuxCopiedMsg, vlen)
	for i := range msgs {
		msg, err := linuxReadMsg(pid, uintptr(req.Data.Args[1])+uintptr(i*linuxMmsghdrBytes))
		if err != nil {
			return linuxNegErrno(err)
		}
		if !linuxLoopbackPermitted(policy, msg.name, resolvers) {
			return -int64(unix.EPERM)
		}
		msgs[i] = msg
	}
	fd, err := linuxDupSocket(pid, target)
	if err != nil {
		return linuxNegErrno(err)
	}
	defer unix.Close(fd)
	var sent int64
	base := uintptr(req.Data.Args[1])
	for i, msg := range msgs {
		n := linuxSendCopied(fd, msg, req.Data.Args[3])
		if n < 0 {
			if sent == 0 {
				return n
			}
			return sent
		}
		// Callers read mmsghdr.msg_len, not the syscall return, for the byte count.
		if err := linuxWriteUint32(pid, base+uintptr(i*linuxMmsghdrBytes)+linuxMsghdrBytes, uint32(n)); err != nil {
			if sent == 0 {
				return linuxNegErrno(err)
			}
			return sent
		}
		sent++
	}
	return sent
}

func linuxWriteUint32(pid int, addr uintptr, value uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	return linuxWriteRemote(pid, addr, buf[:])
}

func linuxCallbackSocket(fd int) bool {
	var raw [128]byte
	n := uint32(len(raw))
	_, _, errno := unix.RawSyscall(unix.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&n)))
	if errno != 0 || n < 2 || n > uint32(len(raw)) {
		return false
	}
	sock, kind := linuxClassifySockaddr(raw[:n])
	if kind != linuxSockIP || sock.port != linuxCodexCallbackPort {
		return false
	}
	if sock.ip.Is4() && sock.ip.As4() == [4]byte{127, 0, 0, 1} {
		return true
	}
	return sock.ip == netip.IPv6Loopback()
}

func linuxLoopbackListen(pid, target int, backlog uint64, policy linuxLoopbackPolicy) int64 {
	if !policy.Callback {
		return -int64(unix.EPERM)
	}
	fd, err := linuxDupSocket(pid, target)
	if err != nil {
		return linuxNegErrno(err)
	}
	defer unix.Close(fd)
	if !linuxCallbackSocket(fd) {
		return -int64(unix.EPERM)
	}
	r, _, errno := unix.RawSyscall(unix.SYS_LISTEN, uintptr(fd), uintptr(int32(backlog)), 0)
	return linuxSyscallResult(r, errno)
}

func linuxLoopbackAccept(listener int, req linuxSeccompNotif, policy linuxLoopbackPolicy) (int64, bool) {
	if !policy.Callback {
		return -int64(unix.EPERM), false
	}
	flags := uint64(0)
	if uint32(req.Data.Nr) == unix.SYS_ACCEPT4 {
		flags = req.Data.Args[3]
		if flags&^uint64(unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK) != 0 {
			return -int64(unix.EPERM), false
		}
	}
	if req.Data.Args[1] != 0 && req.Data.Args[2] == 0 {
		return -int64(unix.EFAULT), false
	}
	fd, err := linuxDupSocket(int(req.PID), int(int32(req.Data.Args[0])))
	if err != nil {
		return linuxNegErrno(err), false
	}
	defer unix.Close(fd)
	if !linuxCallbackSocket(fd) {
		return -int64(unix.EPERM), false
	}
	var peer [128]byte
	peerLen := uint32(len(peer))
	var addrArg, lenArg uintptr
	if req.Data.Args[1] != 0 {
		addrArg = uintptr(unsafe.Pointer(&peer[0]))
		lenArg = uintptr(unsafe.Pointer(&peerLen))
	}
	r, _, errno := unix.RawSyscall6(unix.SYS_ACCEPT4, uintptr(fd), addrArg, lenArg, uintptr(uint32(flags)), 0, 0)
	if errno != 0 {
		return -int64(errno), false
	}
	accepted := int(r)
	defer unix.Close(accepted)
	if req.Data.Args[1] != 0 {
		if err := linuxWriteAcceptedPeer(int(req.PID), req.Data.Args[1], req.Data.Args[2], peer[:peerLen]); err != nil {
			return linuxNegErrno(err), false
		}
	}
	addFlags := uint32(0)
	if flags&unix.SOCK_CLOEXEC != 0 {
		addFlags = unix.O_CLOEXEC
	}
	add := linuxSeccompAddFD{ID: req.ID, Flags: unix.SECCOMP_ADDFD_FLAG_SEND, SrcFD: uint32(accepted), NewFDFlags: addFlags}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_ADDFD, uintptr(unsafe.Pointer(&add))); errno != 0 {
		return -int64(unix.EPERM), false
	}
	return 0, true
}

func linuxWriteAcceptedPeer(pid int, addrPtr, lenPtr uint64, peer []byte) error {
	raw, err := linuxReadRemote(pid, uintptr(lenPtr), 4)
	if err != nil {
		return err
	}
	orig := binary.LittleEndian.Uint32(raw)
	n := len(peer)
	if uint32(n) > orig {
		n = int(orig)
	}
	if n > 0 {
		if err := linuxWriteRemote(pid, uintptr(addrPtr), peer[:n]); err != nil {
			return err
		}
	}
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], uint32(len(peer)))
	return linuxWriteRemote(pid, uintptr(lenPtr), out[:])
}

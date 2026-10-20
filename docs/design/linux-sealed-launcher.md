# Sealed Linux launcher (#187)

[Documentation index](../README.md)

This is the implementation of [roadmap item 6](linux-support.md#stack-2--sandbox-backend).
Qualified `linux/amd64` admission now uses this launcher through the registered
Bubblewrap backend. The internal re-exec markers are not command-line flags.
The implementation is linux/amd64 and uses Go plus Go assembly, without CGO.
Darwin code is unchanged. `linux/arm64` stays closed.

## Boundary

`linuxPrepareBwrap` prepares a command; it never starts one. It reuses the system
Bubblewrap verifier, retains the verified executable descriptor, pins each bind
source with `openat2`, and compares inode identity and mount ID with the compiled
plan. Bubblewrap receives `/proc/self/fd/N` sources, so it cannot retarget a bind
through a replaced host pathname. The fixed arguments require user, mount, PID,
IPC, UTS and cgroup namespaces, drop capabilities, disable subsequent user
namespaces, create private `/dev`/devpts and `/proc`, and seal the synthetic root
read-only. Network namespace sharing preserves outbound and loopback access.
No `--try` operations or weaker retry are used.

Policy, literal target argv and selected environment use a bounded, sealed memfd.
Environment values use the existing `environmentresource` framing, after fixed
HOME/TMPDIR/PATH/locale values; duplicates, reserved names, malformed framing,
unsealed files and trailing bytes are rejected. Values are absent from Bubblewrap
argv and its environment. The seccomp program has its own sealed descriptor.
Bubblewrap installs it immediately before starting the trusted helper.

Inside the completed view, the trusted helper opens Landlock rules against
no-symlink paths and requires the complete ABI 6 filesystem mask, including
TRUNCATE, REFER and IOCTL_DEV, plus abstract-socket and signal scopes. It never
reduces that mask to match an older kernel. Private device rules allow ordinary
null/random I/O and private PTYs, without exposing host PTY paths.

The amd64 assembly boundary blocks signals and forks. Only the parent returns
to Go. The child resets signal dispositions, enables no-new-privileges, clears
capabilities, applies Landlock, closes every descriptor above stdio except the
two private protocol pipes, and installs seccomp again. It then sends `R`, waits
for exactly `S`, closes the gate, restores an empty signal mask and calls
`execve`. The status pipe is CLOEXEC. Every error exits 125; successful exec is
observed as status EOF after readiness. No Go runtime, allocator, scheduler or
signal handler runs in the child between fork and exec.

## Policy and terminal limits

The architecture-checked seccomp filter kills foreign/x32 ABI calls. It denies
listen/accept/accept4, ptrace/process-memory access, pidfd_getfd, key operations,
BPF/perf, mount APIs, setns/unshare, namespace-bearing clone, device creation and
io_uring. `clone3` returns ENOSYS so normal threading libraries can use clone;
its indirect flag structure is never assumed safe. Only IPv4/IPv6 socket creation
is allowed; AF_UNIX stream socketpair remains available for private IPC. Datagram
socketpairs are denied because they can reconnect to host pathname sockets. This closes the
ABI 6 pathname-socket gap, including sockets inserted after a directory scan.

The ioctl allowlist permits termios, window sizes, foreground-group queries and
updates, private PTY operations and bounded descriptor controls. It excludes
TIOCSTI/TIOCLINUX, TIOCVHANGUP, TIOCSCTTY, console redirection and line-discipline
changes, including ioctl requests with ignored high argument bits. Stdio is
pinned and must be a regular file, pipe, terminal or approved null/random device;
connected sockets, directories and unrelated devices are rejected.

This PR does not implement foreground-shell restoration or input-queue cleanup.
Bubblewrap starts a new session. Interactive shell qualification and terminal
ownership/restoration remain required before production use. Blocking TCP listen
and accept does not prohibit UDP bind/reception. There is no egress filtering.

## Loopback enforcement

The launcher keeps the host network namespace. Landlock port rules are not used:
they match a TCP port without a destination and do not cover UDP. Classic BPF
cannot safely dereference a sockaddr. `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is not
used. Another thread can replace an allowed address with loopback before the
kernel reads it.

The target filter returns `SECCOMP_RET_USER_NOTIF` for `connect`, `sendmsg`,
`sendmmsg`, and `sendto` when a destination pointer is present. A NULL `sendto`
destination is a connected send and stays allowed. The child installs that
filter with a listener on a fixed descriptor, tells the trusted helper, and
waits. The helper duplicates the listener with `pidfd_getfd` and brokers it.
The target filter then denies `seccomp`, `prctl(PR_SET_SECCOMP)`,
`process_vm_readv`, and `pidfd_getfd`, so the target cannot install another
filter or answer its own notifications. The Bubblewrap setup filter still
allows those calls: the helper, not the target, is the broker.

For each notification the broker copies at most 128 bytes of sockaddr and a
bounded payload into its own memory. Loopback means 127.0.0.0/8, `::1`, and
IPv4-mapped 127.0.0.0/8. That destination is denied with `EPERM` unless the
port is in `selection.loopbackPorts` or it is TCP/UDP port 53 to an exact
nameserver from the host `/etc/resolv.conf`. Any other destination is emulated
with the copied address, including `AF_UNIX`, so a private socketpair still
fails with `EISCONN` instead of being cut off. `sendmmsg` is denied as a whole
when any destination is denied. Non-empty control messages fail closed.
`listen` and `accept` stay denied unless the operation is managed Codex login,
which may listen and accept only on 127.0.0.1:1455 or `[::1]:1455`. Accept
installs the new descriptor with `SECCOMP_IOCTL_NOTIF_ADDFD` and
`SECCOMP_ADDFD_FLAG_SEND`. Responses use a negative errno in the return value
and never set `CONTINUE`.

Qualified `linux/amd64` uses this destination mediation. This is destination mediation for
loopback, not an egress firewall. UDP bind and reception are still not denied.

## Evidence and remaining gates

Unit tests interpret the complete BPF control flow, including foreign ABIs,
clone flags and ioctl argument widths; test sealed/malformed transport, stdio
validation and pins; and inspect Bubblewrap arguments and source replacement.
The Bubblewrap identity is mocked only for the argument-building test; it starts
no process.

Native primitive tests run a fixed, disposable probe with real Landlock/seccomp:
allowed reads/writes/rename, denied host reads and read-only writes, selected
environment, descriptor sealing, capability removal, non-loopback TCP, denied
loopback TCP/UDP, UDP bind,
private stream socketpair (including refused peer replacement after shutdown),
datagram-socketpair denial, fork/exec inheritance and inherited-PTY termios/window sizes.
Kernel failures, missing rules/exec paths, wrong gates and gate EOF must leave the
target's start marker absent. These tests create no Session and make no namespace
or cgroup-containment claim.

The separate composition test requires the complete existing host probe (native
Ubuntu 24.04, kernel 6.12+, trusted system bwrap and delegated cgroup v2), starts
Bubblewrap atomically inside a fresh delegated cgroup, runs the real compiled
mount plan and requires empty-cgroup evidence before removing that group.
Missing prerequisites skip with a reason only when `ACS_LINUX_NATIVE_REQUIRED`
is unset; setting it to `1` turns the same missing prerequisites into failures.
Use `CGO_ENABLED=0 go test ./internal/launch -run LinuxNative -v` for a static
native helper. A skipped composition test is not Linux qualification.

The full composition was not demonstrated on the implementation host: it is
Debian and lacks a trusted bwrap identity and owned cgroup delegation. The
primitive enforcement tests passed there with Landlock ABI 6. Outstanding gates
include package provenance, complete production snapshot capture/races, the
compiler's conservative exclusion limits, lifecycle supervision, authenticated
settlement/recovery, terminal restoration and exact target qualification. The
test protocol's ready/EOF exchange is not a durable cleanup proof.

Kernel semantics follow the [Linux 6.12 Landlock documentation](https://docs.kernel.org/6.12/userspace-api/landlock.html).
FD bind and seccomp setup follow [Bubblewrap's implementation](https://github.com/containers/bubblewrap/blob/v0.8.0/bubblewrap.c).

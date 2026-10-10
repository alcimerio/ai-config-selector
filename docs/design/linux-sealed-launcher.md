# Sealed Linux launcher (#187)

[Documentation index](../README.md)

This is the implementation of [roadmap item 6](linux-support.md#stack-2--sandbox-backend).
Production Linux admission remains disabled. There is no registered Linux
backend, helper CLI switch, environment bypass, or credential-provider change.
Only the test executable contains the helper entry point. The implementation is
linux/amd64 and uses Go plus Go assembly, without CGO. Darwin code is unchanged.

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

## Evidence and remaining gates

Unit tests interpret the complete BPF control flow, including foreign ABIs,
clone flags and ioctl argument widths; test sealed/malformed transport, stdio
validation and pins; and inspect Bubblewrap arguments and source replacement.
The Bubblewrap identity is mocked only for the argument-building test; it starts
no process.

Native primitive tests run a fixed, disposable probe with real Landlock/seccomp:
allowed reads/writes/rename, denied host reads and read-only writes, selected
environment, descriptor sealing, capability removal, outbound loopback, UDP bind,
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

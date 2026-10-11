# Linux Session containment (#188)

[Documentation index](../README.md)

This implements [roadmap item 7](linux-support.md#stack-3--supervisor-and-containment).
Production Linux launches remain disabled. There is no registered Linux backend,
production helper entry point, bypass flag, or credential-provider change. The
supervisor and namespace helper are linux/amd64 Go code without CGO; Darwin code
and tests are unchanged.

## Ownership and start gate

A dedicated outer supervisor runs outside the target PID namespace and cgroup.
It becomes a child subreaper, opens the calling user's verified cgroup v2
delegation, and creates a random `acs-session-*` leaf. It pins the directory,
`cgroup.kill`, `cgroup.events`, and `cgroup.procs`; records device/inode identity;
and requires empty membership and a working kill control before starting a child.
Missing delegation rejects the launch. No existing processes are migrated and no
systemd-owned ancestor is modified. Child cgroup creation is disabled at the leaf.

The reviewed Bubblewrap command starts atomically with `CLONE_INTO_CGROUP` and
`CLONE_PIDFD`. There is no numeric-PID placement interval or process-group
fallback. Bubblewrap supplies PID 1 and a private `/proc`; the trusted helper
beneath it also becomes a subreaper. That helper starts the existing sealed
Landlock/seccomp boundary, acquires its pidfd before releasing its gate, and keeps
the outer protocol separate from the restricted child's local start/status pipes.
The target inherits none of the cgroup or supervisor descriptors.

The outer supervisor verifies the live command's membership before reporting
readiness. Only a subsequent owner start byte releases the restricted child.
The helper reports successful exec separately from readiness, then relays the
actual target wait status. Interrupt, terminate, hangup, quit, and window-change
signals travel through this private channel to the target's pidfd. Bubblewrap's
encoded shell exit code is not used to reconstruct target signal status.

## Settlement and failure

Target completion, owner-channel EOF, cancellation, malformed frames, and setup
failures all enter cleanup. The supervisor uses the pinned `cgroup.kill` control,
waits for its direct child, checks pidfd death, reaps adopted descendants until
`ECHILD`, and requires `cgroup.events` to report `populated 0` with empty
`cgroup.procs`. Only then may it remove the original cgroup. An absent or replaced
path is an error, never evidence of successful cleanup; numeric PIDs are never
used to kill a discovered process tree.

Cleanup has a bounded wait. Failed controls, identity discontinuity, unreadable
evidence, or a timeout return an unsettled result and a quarantine error. A pidfd
kill of the original command is only best effort after such a failure. It cannot
turn an unsettled result into success. The caller must retain its Session when
`Settled` is false, including when a valid target exit status was received.

The supervisor now requires the [authenticated cleanup owner](linux-cleanup-recovery.md)
from roadmap item 8. It binds the cgroup before start and publishes durable proof
only after settlement and terminal restoration. Abrupt loss of the outer
supervisor cannot produce successful settlement evidence. Bubblewrap's
parent-death behavior is defense in depth and is not accepted as cleanup proof.

## Evidence and remaining qualification

Unit tests cover start ordering, membership rejection, duplicate/invalid frames,
owner and helper loss, cancellation, exit/signal status, replaced/missing cgroup
paths, non-cgroup delegation, and every independent settlement prerequisite.
The filesystem replacement test uses ordinary files; settlement-failure tests
inject kernel outcomes. They do not claim native cgroup confinement.

Native primitive tests exercise real pidfds, a stale pidfd with an unrelated live
process, subreaper setup, the sealed start gate, gate-EOF abort, signal forwarding,
and exact exit status. The composition test requires all host prerequisites and
uses the real system Bubblewrap, compiled filesystem plan, Landlock/seccomp, and
per-Session delegation. It exercises fork/setsid and double-fork descendants,
membership, owner process death, unrelated-process survival, and cgroup removal
after completion or pre-start abort.

Run with `CGO_ENABLED=0 go test ./internal/launch -run 'LinuxNative' -v`.
Unavailable native prerequisites skip with a reason only when
`ACS_LINUX_NATIVE_REQUIRED` is unset; a required gate fails instead. On the
implementation host, native pidfd and sealed-helper tests passed, and missing
delegation refused allocation. Full composition was skipped: the host is Debian,
with no trusted system Bubblewrap or owned cgroup delegation. Fork/setsid and
owner-loss confinement therefore still require native qualification on Ubuntu
24.04 HWE; no production support is claimed.

The lifetime checks follow the [Linux 6.12 cgroup v2 semantics](https://docs.kernel.org/6.12/admin-guide/cgroup-v2.html),
including the distinction between live membership and unreaped zombies.

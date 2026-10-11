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

The kill preflight uses a disposable sibling, which is removed before allocating
the fresh Session leaf. It never writes `cgroup.kill` in the leaf before placing
the child there. In the [Linux 6.17 implementation](https://github.com/torvalds/linux/blob/v6.17/kernel/cgroup/cgroup.c),
even killing an empty cgroup increments its kill sequence. `cgroup_css_set_fork`
can capture the source cgroup's sequence before selecting the destination, and
`cgroup_post_fork` compares it to the destination's sequence. A pre-killed leaf
can therefore cause the atomically placed child to receive SIGKILL before exec.
The prerequisite probe and the earlier Bubblewrap composition fixture placed
their children before killing, so they did not exercise this startup failure.
The separate preflight preserves the real kill check without reusing that group.

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

The init's `X` frame ends target-status collection; it is not forwarded as a
settlement report. The outer supervisor keeps the owner channel open through
cgroup cleanup, terminal restoration and durable proof publication, then sends
the owner's final `X` byte. Failed settlement or proof publication closes the
channel without that success byte. Previously the status reader consumed `X`
and returned without any final owner report, so successful recipe helpers exited
zero while their callers received EOF. The direct-init and result-file tests did
not assert this outer report; recipe and target qualification now share it.

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

`TestLinuxNativeSessionCgroupStartup` separately requires a helper to reach
readiness after the real allocation/kill preflight with atomic cgroup placement
and a pidfd. It then checks membership, cgroup kill, SIGKILL status, pidfd death,
empty membership and removal. This regression still requires native delegation;
unit tests are not evidence that it passes on the qualification runner.

Native protocol assertions collect the supervisor's completed exit status and
stderr/stdout, including the contained helper's log or PTY output. Setup errors
identify the allocation, cleanup-binding, clone, membership or protocol step and
preserve syscall errors. The raw restricted child sends only a fixed stage code
and errno on its private failure channel; it still exits without entering Go or
executing the target. EOF before `R` now includes these diagnostics rather than
hiding the helper's error behind the protocol mismatch.

For the #191 runner evidence, an empty scope `cgroup.subtree_control` does not
trigger the [no-internal-process constraint](https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint):
that constraint applies when distributing domain controllers. The Session uses
core membership/kill controls and does not enable controllers or move the scope's
existing processes. The passed probes also exercised user namespaces, pidfds and
Bubblewrap; redirected stdio and static helpers have their own passing primitive
tests. Those observations narrow the investigation but do not replace a rerun
of the complete Session tests on the affected host.

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

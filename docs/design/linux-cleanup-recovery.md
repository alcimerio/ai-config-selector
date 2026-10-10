# Linux authenticated cleanup and recovery (#188)

[Documentation index](../README.md)

This implements [roadmap item 8](linux-support.md#stack-3--supervisor-and-containment)
on the existing Linux containment primitives. Production Linux launches remain
disabled: there is no registered backend, production helper entry point, bypass
flag, credential-provider change, or release/support expansion. Darwin uses its
existing proof verifier, supervisor and terminal implementation unchanged.

## Cleanup ownership and durable evidence

The dedicated outer supervisor requires a cleanup owner holding a Session lease
reference. Preparation requires the caller's exact, already-prepared 32-byte
operation challenge and sole lease ownership. It durably protects the Session
against abandoned-directory cleanup, pins its private root directory, publishes
a fresh binding, and durably removes the no-target proof before starting any
child. The target's filesystem view excludes this state and the descriptors are
close-on-exec.

The private binding contains a random generation, kernel boot ID, Session root
device/inode, and, before child creation, the delegated parent and target cgroup
device/inode plus cgroup name. It is authenticated with HMAC-SHA256 using the
shared operation challenge. Binding and settlement use distinct MAC domains:
copying readable binding bytes into the proof location cannot forge settlement.
The challenge is never written into the Linux binding or settlement proof.

The completion sequence is:

1. Close the helper control channel and terminate the pinned target cgroup.
2. Wait for the directly owned child, verify its pidfd is dead, and reap adopted
   children until `ECHILD`. Require `populated 0` and empty `cgroup.procs` from the
   original, identity-checked cgroup before removing it.
3. Restore the explicitly supplied controlling terminal's saved attributes,
   flush pending input, and restore the original foreground process group.
4. Revalidate the boot, root and current generation binding, write the
   authenticated settlement proof using an exclusive 0600 temporary file, sync
   the file, rename relative to the pinned root, and sync the directory.
5. Release the retained lease reference and signal `CleanupDone`. Only then can
   a requested Session removal or higher-level credential finalization proceed.

Failures before child creation can prove that no target started. An uncertain
cgroup allocation or binding still quarantines. A normal/signaled target exit
is independent of successful cleanup and never substitutes for its proof.

## Quarantine and recovery

Timeout, cancellation, lost owner, protocol failure and target completion all
enter the same bounded containment cleanup. Cancellation does not cancel the
cleanup attempt itself. Any failed fact, persistence error or terminal-restore
error signals `CleanupUnproven`; `CleanupDone` stays open. The in-process
quarantine retains the lease and pins, and the durable protection survives owner
exit. A later callback cannot promote a failed generation to success.

The shared recovery workflow still obtains its operation capability and native
Session lease before calling `VerifySessionCleanupProof`. On Linux the verifier
requires matching authenticated binding/proof, challenge, generation, root
identity and current boot. Evidence must be bounded, regular, singly linked,
owned by the current user and mode 0600; symlinks and malformed data fail closed.
Recovery syncs evidence and its directory before accepting it.

A missing proof retains the Session, even if the original cgroup has vanished.
A missing binding cannot validate a Linux settlement proof. A replayed prior
generation fails, including when a caller reuses the same challenge. Recovery
does not kill a cgroup reopened by name, infer success from an absent PID or
cgroup, reconstruct missing proof, or authorize recovery across a reboot.
Those cases require a separately reviewed recovery rule. A crash after cgroup
removal but before proof publication deliberately retains the Session.

Legacy prepared no-target proofs remain supported before the Linux cleanup
owner is armed. Re-arming requires a fresh prepared operation and sole lease
ownership. If a new operation crashes between publishing its prepared proof and
replacing the preceding Linux binding, recovery conservatively retains it.

## Terminal handling and evidence

Terminal capture pins only an explicitly inherited controlling terminal. Files
and pipes remain redirected; no host terminal path is reopened. Restoration
blocks `SIGTTOU` only on its locked OS thread and restores that thread's previous
mask. Attribute restoration is immediate rather than waiting indefinitely for
output drain. Pending input is discarded before foreground ownership returns.
Unknown process settlement prevents terminal restoration and retains the pin.
Full interactive Bubblewrap job-control integration remains an activation gate.

Unit tests use real private files, locks and authenticated proofs with injected
cgroup/pidfd/reaping outcomes. They cover independent cleanup failures, bounded
waits, publication ordering, retained leases, stale generations, replay,
reboot/root mismatch, missing/corrupt proof and persistence failure. These tests
do not establish native cgroup containment or power-loss durability.

A native PTY helper changes terminal attributes and foreground ownership, queues
input through the PTY master, and verifies saved attributes, restored ownership
and an empty input queue. It requires neither Bubblewrap nor cgroup delegation.
The optional native containment composition additionally verifies authenticated
recovery after abort, signal/descendant cleanup, owner loss and cancellation, and
retention after outer-supervisor loss. It requires all existing Linux probes.
Unavailable prerequisites skip explicitly only when `ACS_LINUX_NATIVE_REQUIRED`
is unset; required native runs fail instead. Skipped composition is not Linux
qualification. No Ubuntu HWE certification, credential-provider qualification,
or production enablement is claimed by this change.

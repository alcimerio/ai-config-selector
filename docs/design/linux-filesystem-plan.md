# Linux filesystem compiler (#187)

[Documentation index](../README.md)

This implements the pure planning portion of [roadmap item 5](linux-support.md#stack-2--sandbox-backend).
It does not enable Linux launches, register a backend, or demonstrate native
containment. The implementation and tests are Linux-only; the shipped macOS
runtime authority and backend are unchanged.

`internal/launch/filesystem_plan_linux.go` consumes the filesystem fields of a
resolved request, an explicit prospective Linux runtime authority, and a complete
canonical filesystem snapshot. It returns ordered Bubblewrap mount operations,
Landlock rules, ancestor guards, and mandatory socket restrictions. Errors return
an empty plan and source-free diagnostics. It never reads or modifies host files,
allocates a Session, or invokes a process.

The input snapshot includes source identities, immediate directory entries,
mount IDs, and filesystem types. Capturing and revalidating that snapshot, pinning
source descriptors, and translating the plan into kernel operations belong to
the sealed launcher.
The compiler cannot establish snapshot completeness or eliminate host races.

## Accepted plans

- Explicit read-only or read-write workspace/Path authority, read-only executable
  and runtime inputs, and private writable Session HOME and temporary trees.
  Only explicit runtime inputs are imported; no blanket `/usr`, real home,
  `/run`, host `/proc`, or cgroup mount is added. Shared Profile grants compose
  by union. Runtime inputs cannot overlap writable authority.
- An empty private root, synthetic ancestors, explicit source binds, and a final
  read-only remount of the private root. Writable binds remain separate mounts.
  Synthetic ancestors carry only Landlock directory-read authority. The final
  root seal also prevents their metadata modification and replacement.
- Exclusions beneath read-only authority. The compiler reconstructs each branch
  leading to an exclusion using synthetic directories and binds its allowed
  siblings individually. It never binds an ancestor containing denied data.
  Existing excluded names are omitted; absent names and absent ancestors stay
  absent. No host placeholder is needed. Disjoint writable subtrees retain their
  authority. The reconstructed ancestors are immutable, guarding rename,
  removal, and symlink substitution by the target.
- A fixed ABI 6 filesystem mask, including `REFER`, `TRUNCATE`, and `IOCTL_DEV`,
  with abstract-socket and signal scoping. Read-only rules never grant mutation;
  ordinary writable trees do not grant device creation or device ioctls.
  Newer ABIs do not silently change the mask.

## Rejection gates and remaining work

- Writable directories containing exclusions or protected MCP/auth Session
  paths are rejected. Landlock allow rules cannot subtract a child, and making
  the containing directory read-only would revoke ordinary allowed creation.
  This also means current protected target Session layouts are not admitted.
  Global MCP configuration basename reservations are rejected rather than
  approximated with a finite scan.
- Aliased paths, symlinks, multiply-linked files, special files (including
  sockets), kernel interface filesystems, nested mounts, incomplete listings,
  and conflicting private credential-store/supervisor paths are rejected. These
  are conservative planning limits, not new restrictions on macOS Profiles.
- Every plan requires explicit Unix-socket denial. A future launcher must block
  `socket(AF_UNIX)` and alternative creation via io_uring, and seal inherited and
  received descriptors so no host socket enters the target. Private `socketpair`
  IPC can remain available. A directory scan cannot prevent a host from adding
  a socket after capture; ABI 6 alone does not mediate pathname connections.
  This is a required future enforcement mechanism, not a claim that seccomp is
  implemented here. See the [Linux 6.12 Landlock contract](https://docs.kernel.org/6.12/userspace-api/landlock.html).
- All containment requirements remain: trusted system Bubblewrap, Linux 6.12+
  on a qualified amd64 host, no WSL/containers, sealed single-threaded setup,
  complete seccomp and descriptor policy, and delegated cgroup v2 settlement
  before Session or credential cleanup. No production activation follows from
  a successful compilation.

The unit suite uses synthetic snapshots and validates accepted authority,
reconstruction, immutable ancestors, fixed rights, deterministic output, and
failure gates. It does not mount filesystems, install Landlock/seccomp, or prove
the future socket policy. Native allowed/denied controls and race tests remain
required before the sealed launcher or any support claim is admitted.

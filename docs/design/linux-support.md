# Restoring Linux support

[Documentation index](../README.md)

Status: proposed; no Linux runtime or release support is added by this document.
Research baseline: `c5477ebb4b0115b83617cd15c1966eeb34256256`, 2026-10-09.
Repository citations use `path:line` at that commit unless a historical ref is
specified. External references were checked on the research date. This was a
read-only investigation; no builds, native probes, or target installers were run.

Recommendation: retain the shared launch contract; implement a Linux backend
combining a private filesystem view, Landlock, seccomp, and supervised process
containment. Prefer verified system Bubblewrap for namespace setup over writing
a new mount launcher. Initially qualify Linux 6.12+ with Landlock ABI 6+, cgroups
v2 delegation, and working unprivileged namespaces. These are proposed floors,
not sufficient conditions: probe the actual features and reject missing ones.
Keep Linux execution disabled until the complete composition passes native
tests, especially exclusions, Unix sockets, credentials, and supervisor loss.

## 1. What changed, and why

- Linux support was introduced by `ef46099` ("support Linux and portable terminal
  behavior", #46). At `v0.3.3`, Ubuntu 24.04 LTS on amd64 and arm64 required
  verified signed-system Bubblewrap; other distributions and WSL were excluded.
  See [`v0.3.3:docs/releases/v0.3.3.md:47-58`][history-033].
- `9a99532124966043e9a63041773cc74071c54c0c` (#80, macOS sandbox shell) removed
  Linux from `ValidatePlatform`, GoReleaser's OS list, installer acceptance, and
  native release matrices. The `v0.3.3..v0.4.0` diff shows these changes together.
  [`v0.4.0:docs/releases/v0.4.0.md:43-55`][history-040] explicitly calls v0.3.3 the
  last supported Linux release and retains Bubblewrap only as unsupported code.
  The [v0.4.0 checklist:19-25][history-checklist] requires macOS-only artifacts
  and a nonblocking Linux compilation observation.
- `786e8193e5493416e806f9db04cdaf3ca7d8c0af` (#131, 2026-09-30) subsequently
  [deleted the unsupported Linux backend][history-removal]: `bubblewrap.go`,
  `bubblewrap_helper_linux.go`, `bubblewrap_helper_other.go`,
  `bubblewrap_supervisor_linux.go`, `sandbox_backends_linux.go`, their tests, and
  `acceptance/promoted_artifact_native_linux_test.go`. These were not deleted
  in the v0.4.0 transition itself.
- Current support is narrower still: macOS 26 Apple Silicon only, with no support
  for historical Linux or Intel assets (`SECURITY.md:15-22`,
  `README.md:27-30`, `docs/releases/v0.5.0.md:87-92`).

The documented reason is a deliberate narrowing of the supported, natively
validated release surface to macOS alongside the new shell. The inspected
commits/release notes do not establish a Linux vulnerability, an upstream
Bubblewrap failure, or a specific staffing rationale. Do not invent one.
Deletion later removed an already unsupported implementation; it did not itself
revoke a then-supported Linux release.

There is no current `CHANGELOG.md`; release history is under `docs/releases/`,
and GoReleaser changelog generation is disabled (`.goreleaser.yaml:55-56`). Old
release notes removed from the working tree remain available through git.

Historical code is useful evidence, not a ready-to-revert solution. For example,
`v0.3.3:internal/launch/bubblewrap.go:37-85` bound the workspace writable, mounted
all `/usr` read-only, and put environment entries into `--setenv` arguments.
Current Profiles have read-only defaults, exclusions, protected MCP inputs,
selected secret transport, and named Codex authentication to preserve.

## 2. Current architecture and portability boundaries

### Existing interfaces

`internal/launch/sandbox.go:287-310` defines `ProcessRequest`: validated intent,
Session paths, runtime inputs, grants/exclusions, protected Session paths,
environment lease, recovery challenge, executable/arguments, and terminal.
`ProcessSandbox` exposes `Readiness`, `Check`, and `Prepare` at lines 393-399;
`Process` exposes `Start`, `Wait`, and `Signal` at lines 371-376. Optional
`ProcessCleanup` and `ProcessCleanupUnproven` interfaces at lines 378-390 retain
ownership when cleanup continues or can no longer be proved.

The private `sandboxBackend` interface is already `check`/`prepare`
(`internal/launch/sandbox.go:415-418`). `NewProcessSandbox` owns selection;
callers cannot choose an unchecked backend (lines 433-445). Extend this boundary
instead of adding target-specific Linux execution paths.

### Files requiring platform treatment

| Area | Exact current files and evidence | Linux work |
| --- | --- | --- |
| Selection | `internal/launch/sandbox.go:223-267,478-497`; `internal/launch/sandbox_backends_darwin.go:1-7`; `internal/launch/sandbox_backends_other.go:1-5` | macOS-only admission; `!darwin` returns no backend. Add a Linux registration only after qualification. |
| Policy/launch | `internal/launch/seatbelt_darwin.go:1,31-37,60-90,93-126,858,1042` | Darwin build tag, `/usr/bin/sandbox-exec`, Seatbelt policy and process implementation. Implement separately. |
| Supervisor | `internal/launch/seatbelt_supervisor_darwin.go:1,27-75,140,598-778` | Darwin helper entrypoints, descriptor sealing, process identity ledger and settlement. Preserve protocol properties, replace process APIs. |
| Process inspection | `internal/launch/seatbelt_proc_darwin.go:1,74` | Loads `/usr/lib/libSystem.B.dylib`; Darwin process enumeration is not portable. |
| TTY | `internal/launch/seatbelt_terminal_darwin.go:1,16-44`; `internal/launch/seatbelt_darwin.go:785-823` | Descriptor pinning, devfs identity, Darwin ioctls and input flushing need Linux equivalents. |
| Runtime authority | `internal/launch/sandbox.go:319-368` | Shared file encodes `bounded-macos-runtime`, macOS DNS, sysctl and Mach grants. Split semantic contract from platform realization; update authority digest inputs. |
| Executor | `internal/executor/executor.go:36,136-181,206-226,259,388`; `internal/executor/codex_auth_contained.go:63,131` | Shared orchestration already uses the interface. `/bin/zsh` and `-f` are macOS shell choices; Unix signals/WaitStatus are usable on Linux. |
| Shell/help | `internal/sandboxshell/sandboxshell.go`; `internal/cli/commands.go:67` | Fixed shell descriptions/recipe must agree with a reviewed Linux shell, e.g. `/bin/bash --noprofile --norc`. Never use ambient `$SHELL`. |
| Credential provider | `internal/codexauthresource/keychain_darwin.go:1,92-105`; `internal/codexauthresource/keychain_other.go:1-5`; `internal/codexauthresource/keychain_provider.go:29-71` | Security/CoreFoundation via purego; non-Darwin provider is unavailable. Introduce Linux provider behind the existing store seam. |
| Credential store | `internal/codexauthresource/store.go:24-45,78-86` | Provider interface exists, but production constructor hardcodes Keychain. Locks, markers and validated projection should remain shared. |
| Diagnostics | `internal/diagnostics/host_darwin.go`; `internal/diagnostics/host_other.go:1-12`; `internal/diagnostics/files_unix.go` | Add Linux feature reporting; don't confuse a platform label with backend readiness. |
| Distribution | `.goreleaser.yaml:5-20`; `internal/selfupdate/update.go:111-139`; `scripts/install.sh.tmpl:36-42,155-168` | macOS-only build, updater and installer predicates; change together at release time. |

Existing Linux shims should be preserved: `internal/launch/path_grants_open_linux.go:1-9`,
`internal/launch/executable_ctime_linux.go:1-7`,
`internal/exchangefile/rename_linux.go`,
`internal/codexauthresource/rename_noreplace_linux.go`, and
`internal/executor/codex_auth_rename_noreplace_linux.go`. Their Darwin siblings
are separate implementations. `internal/builder/terminal_linux_test.go` and
`internal/executor/devin_launch_linux_test.go` are tests, not a Linux sandbox.

### Reusable core

Keep Profile codecs, category resolution, immutable authority planning, exchange,
history, materialization, and lifecycle shared: `internal/commonprofile/registry.go:13-82`,
`internal/authority/plan.go`, `internal/category/`, `internal/profile/`,
`internal/profilerepo/`, `internal/profileexchange/`, `internal/skillmaterial/`,
`internal/session/session.go:20-49,133-188`, and `internal/sessionops/`.
Many are Unix-portable, not OS-independent: descriptor operations and file locks
still need native validation on both OSes.

Share grant validation in `internal/launch/path_grants.go`,
`internal/launch/path_exclusions.go`, and `internal/launch/executable_grants.go`;
environment framing in `internal/environmentresource/resource.go:118-199`;
lease retention in `internal/launch/session.go:391-500`; and recovery framing in
`internal/launch/recovery_proof.go:12-45`. Reuse the Devin/Codex adapters and
`internal/genericrun/`, while reviewing their platform runtime dependencies.

Current Ubuntu CI is only nonblocking compile observation: it uses `go test -c`
and builds `cmd/acs`, never executes tests (`.github/workflows/ci.yml:17-42`).
A manual check at the research baseline found that `GOOS=linux go build ./...`
succeeds and `go test ./...` passes on a Linux amd64 host, because the macOS
backend is excluded by build tags and Linux has no registered backend.

## 3. Security contract and sandbox choices

Required parity comes from `SECURITY.md:52-72` and
`docs/reference/security-model.md:10-30,64-99,121-125`:

- Deny filesystem authority by default; expose bounded runtime inputs, selected
  read/write paths, and the private writable Session. Enforce exclusions and
  protected inputs even inside otherwise writable grants.
- Every probe, login/status operation, shell, target and descendant stays
  contained. Missing features, invalid policies, or uncertain setup stop launch.
  No direct-exec escape hatch or automatic weaker-backend retry.
- Only selected credentials/environment reach the Session. No ambient host home,
  global Codex identity, agent sockets, desktop bus or inherited extra FDs.
- Keep lease and credential quarantine until process settlement is proven.
- Outbound networking remains available; destination/egress filtering is outside
  scope (`docs/reference/security-model.md:37-45`). This does not authorize host
  Unix sockets, desktop automation, inbound listening, or unrelated process access.

### Landlock

Landlock is an unprivileged, inherited LSM restriction. Its useful upstream
milestones are below; kernel numbers are introduction points, not probes or
guarantees about vendor builds/backports.[landlock-abi][landlock-612]

| ABI | Upstream kernel | Relevant addition |
| --- | --- | --- |
| 1 | 5.13 | Initial filesystem rights. |
| 2 | 5.19 | `REFER`: cross-directory link/rename control. |
| 3 | 6.2 | `TRUNCATE`: necessary for read-only semantics. |
| 4 | 6.7 | TCP bind/connect port rights; not an egress policy by itself. |
| 5 | 6.10 | `IOCTL_DEV`: coarse device ioctl control. |
| 6 | 6.12 | Abstract Unix-socket and signal scoping. |
| 7 | 6.15 | Audit/logging controls. |
| 8 | 7.0 | Thread-synchronized enforcement (`TSYNC`). |
| 9 | 7.1 | Pathname Unix-socket connect control (`RESOLVE_UNIX`). |

The current upstream manual also describes ABI 10 (UDP rights/quiet logging)
and 11 (combined no-new-privileges flag). They are not prerequisites here; do not
infer deployed-kernel availability from an unversioned manual.[landlock-current]

Query `landlock_create_ruleset(..., LANDLOCK_CREATE_RULESET_VERSION)`; reject
`ENOSYS`, disabled LSM, and insufficient ABI. Build a tested handled-rights mask,
not a mask silently reduced to the host's capabilities. Require no-new-privileges
before untrusted exec; fork/exec descendants inherit restrictions. Before ABI 8,
apply Landlock in a dedicated single-threaded launcher: an arbitrary Go goroutine
does not confine other runtime threads.[landlock-current][landlock-612]

Landlock alone cannot supply the ACS boundary. ABI 6 lacks pathname socket
mediation; already-open FDs survive; metadata/mutation operations such as chmod
are not all mediated. Allow rules cannot subtract a forbidden child from an
allowed parent. The filesystem view and read-only mounts must close those gaps.
These limitations are reasons for composition, not permission to drop promises.
[landlock-612][landlock-current]

### seccomp-bpf

Seccomp filters syscall numbers and scalar arguments, not path strings or memory
pointed to by arguments; it is not a filesystem policy. Use an architecture-checked
filter after trusted setup to reduce kernel attack surface and deny dangerous
operations: namespace changes/mounts, ptrace/process-memory access, `pidfd_getfd`,
`open_by_handle_at`, and unneeded BPF/perf/io_uring operations. Audit syscall
alternatives and compat ABIs. Preserve normal threads, fork/exec, DNS and terminal
behavior; `clone3`'s pointed-to flags need a deliberate policy, not an assumed
scalar check. Fail filter installation closed.[seccomp]

Explicitly deny `ioctl(TIOCSTI)` and dangerous terminal detachment such as
`TIOCVHANGUP`; permit the tested termios/resize/job-control operations. Do not rely
on a distro sysctl or Landlock's coarse ioctl right to separate these requests.
Seccomp inheritance is useful defense but supplies no cleanup proof.[tty][seccomp]

### User/mount namespaces and Bubblewrap

Unprivileged user namespaces date from Linux 3.8; actual availability depends on
kernel configuration, policy and quotas. Use them only for trusted setup, then
drop capabilities. Build an empty private mount view with read-only runtime
binds, explicit writable grants, private tmp/devpts, and PID-namespace `/proc`.
Never expose the host `/proc`, entire `/run/user/$UID`, or a writable cgroup mount.
Hide the real home, SSH/GPG agents, Docker socket and session/system D-Bus.
[userns][bubblewrap]

Bubblewrap provides this setup and an init/reaper; it is a mechanism whose
arguments define the policy. Prefer a reviewed `/usr/bin/bwrap`, verified ownership,
permissions, package provenance and required features, over an arbitrary PATH
binary. Do not depend on Codex's bundled bwrap as ACS's trust root. Supply seccomp
through an FD, and selected secrets through the existing private framing after
setup, never `--setenv SECRET=value` in observable argv.[bubblewrap]

The historical verifier may inform package checks, but Ubuntu package presence
does not prove namespace access. Do not prescribe globally disabling AppArmor,
enabling setuid bwrap, or running ACS as root to pass readiness.

### Recommended composition and hard gates

Prefer ABI 6+/Linux 6.12+ plus Bubblewrap user/mount/PID namespaces and seccomp.
Landlock constrains runtime file authority, read-only mounts enforce VFS writes,
namespaces hide host objects, and seccomp restricts syscalls. cgroups and a trusted
supervisor provide lifetime control. Validate each layer before releasing the
target's start gate. This is a proposed design, not established containment.

Exclusions are a design gate: existing and absent paths, excluded ancestors,
symlink aliases, and protected MCP recipes must behave like the common Profile
contract (`internal/launch/path_exclusions_test.go:11,61,107,183`). A bind mask
over an existing file is insufficient for an absent exclusion; creating a
placeholder in the user's workspace is unacceptable. A private namespace view
must also prevent ancestor rename/removal and preserve ordinary allowed writes.
Prototype and prove this before choosing the final compiler. If equivalent
semantics require another mechanism or higher floor, revise the design; reject
unsupported plans before Session creation rather than silently omitting rules.

### Network, Unix sockets and terminal parity

Current Seatbelt allows local IP bind and coarse outbound IP/DNS, but has no
listen grant; unrelated Unix sockets remain denied
(`internal/launch/seatbelt_darwin.go:1090-1099`). Linux should preserve outbound
TCP/UDP and DNS, test host loopback reachability explicitly, and deny new listeners
with seccomp. Blocking `listen` alone does not restrict UDP reception; record that
distinction and test it. Do not advertise loopback isolation or an egress firewall.

Private mounts hide pathname Unix sockets; ABI 6 scopes abstract sockets.
Audit sockets reachable inside writable grants too: on ABI 6, hiding `/run` alone
does not prevent a socket placed in the workspace. Either reject such exposure,
prove an additional mediation mechanism, or require ABI 9 pathname scoping.
SCM_RIGHTS and inherited connected sockets also need tests. DNS should use bounded
resolver files/direct IP, without granting desktop-bus access.

Pin only inherited terminals, give children private devpts, and preserve redirected
stdio without adding pathname grants. Keep PTY pins until cleanup. Deny TIOCSTI
even on attached terminals; flush pending input before restoring the foreground
group. A new session alone does not establish interactive parity.[bubblewrap][tty]

The macOS adversarial suite distinguishes assertions from observations:
`TestSeatbeltVerifiesInboundConnectionsAreNotAccepted` asserts no accepted TCP
connection (`internal/launch/seatbelt_denials_darwin_test.go:177-217`);
`TestSeatbeltReportsDetachedDescendantAfterSupervisorLoss` retains quarantine and
may skip for a surviving descendant (lines 220-248); terminal input queue and
absent-spelling reports also contain skip paths (lines 254-288,295-332).
`80cca54` added input-discard hardening; `a3fb328` hardened exclusion spelling;
`36872cd` added the denial gate. Do not describe these reports as proof that every
host prevents TIOCSTI or that killing a supervisor always kills descendants.

## 4. Supervisor, containment and Session quarantine

Use a trusted outer supervisor outside the target PID namespace and Landlock
domain, with a per-Session target cgroup. Keep its control/proof FDs, host resources,
and credential-store access out of the target. A namespace init reaps children;
the outer process owns cleanup and evidence.

| Primitive | Role and limits |
| --- | --- |
| cgroups v2 | Stable membership across fork, double-fork and `setsid`; processes must enter before untrusted exec. Hiding the cgroup namespace is not access control: deny migration handles and writes. |
| `cgroup.kill` | Available since Linux 5.14; recursively SIGKILLs a domain cgroup despite concurrent forks. Wait for `cgroup.events` populated=0 and reap owned children; sending kill is not settlement proof. |
| systemd delegation | Obtain a delegated service/scope subtree (`Delegate=yes`) through the user manager or documented admin setup. Never manipulate arbitrary systemd-owned cgroups. No delegation means unavailable backend in the initial design. |
| pidfd | `pidfd_open` dates from 5.3; signal/wait on stable process references instead of reused numeric PIDs. It identifies one process, not every descendant. Acquire while the child is held, or use supported atomic creation. |
| `PR_SET_CHILD_SUBREAPER` | Since 3.4, reparents orphan descendants for wait/reaping. It neither confines nor reliably enumerates a live subtree by itself. |
| PID namespace | Limits process visibility; death of namespace PID 1 kills members. It complements cgroups and reaping, not host credential isolation or a durable proof by itself. |

Sources: [cgroups v2][cgroups], [kernel 5.14 interface][cgroup-kill-514],
[systemd delegation][delegation], [pidfd][pidfd], [subreaper][subreaper],
[PID namespaces][pidns]. Do not use process groups or `Pdeathsig` alone: both fail
to represent the full Session tree. A thread-parent death signal also needs careful
handling around a multithreaded Go runtime.

Proposed lifecycle:

1. Probe features and compile the plan before allocating a Session. Acquire
   delegation and pin its identity; create an unguessable Session cgroup and
   challenge. Hold trusted launcher execution until membership is confirmed.
2. Prepare mounts/namespaces, seal descriptors, install Landlock/seccomp and drop
   privileges. Clear the prepared no-target proof durably before any target exec.
3. Complete the authenticated ready/start handshake; transfer selected environment
   privately. The target inherits only approved stdio and explicit target inputs.
4. Forward intended signals; preserve normal/signaled exits. On completion or
   owner loss, terminate the cgroup, reap, verify emptiness and namespace shutdown.
5. Write challenge-bound proof only after all target processes are gone. Destroy
   cgroup/mount resources, then allow the shared lease/projection finalization.

This maps to `internal/launch/seatbelt_supervisor_darwin.go:27-57,238-259,792-816`,
`internal/launch/recovery_proof.go:24-29`, and
`internal/launch/session.go:391-500`. Preserve `CleanupDone` versus
`CleanupUnproven`, bounded waits, cancellation and terminal restoration.

If proof, delegation, supervisor, or identity continuity is lost, retain the
Session and credential quarantine; never convert "leader exited", "PID absent",
or "cgroup path absent" into success. Recovery must authenticate the Session
generation/challenge and recorded boot/cgroup identity. A same-boot missing or
recreated group is ambiguous. Reboot-based recovery needs its own reviewed rule.
Protect the original generation if a later launch reuses names.

## 5. Credential storage and headless operation

Separate platform provider selection from credential semantics. Keep
`credentialProvider` (`internal/codexauthresource/store.go:24-31`), exclusive
identity locks, validated metadata, atomic creation/replacement, projection
readback, same-identity refresh and quarantine shared. The production store
currently selects Keychain at line 86; non-Darwin is intentionally unavailable.

| Provider | Fit | Required behavior |
| --- | --- | --- |
| Secret Service/libsecret | Desktop keyrings via session D-Bus; collections may need unlock prompts. | Trusted ACS alone talks to the service; unavailable/locked/missing bus returns a sanitized failure. Test duplicate attributes and provider races against atomic identity semantics. |
| Private file store | Predictable headless/SSH use, without GUI or D-Bus. | Explicitly selected plaintext-at-rest provider; directory 0700, files 0600, validated ownership, no-follow descriptor access, bounded regular files and link counts, atomic no-replace/replace plus fsync. |

Secret Service is a protocol; libsecret is a client implementation. A C binding
changes today's `CGO_ENABLED=0` distribution assumptions; a reviewed Go D-Bus
client avoids that build dependency but still needs protocol/security review.
Secret Service does not inherently provide ACS's complete transactional contract.
[secret-service][libsecret]

Proposed file location: `$XDG_DATA_HOME/acs/credentials/`, default
`~/.local/share/acs/credentials/`. Recovery metadata can use
`$XDG_STATE_HOME/acs/`; these are proposed new paths, not existing behavior.
Reject relative XDG overrides and unsafe parents. Keep runtime sockets/locks out
of durable credential storage; `$XDG_RUNTIME_DIR` is ephemeral.[xdg]
Do not relocate existing `~/.acs` Profiles/Sessions as an incidental Linux port.

Choose the provider explicitly and persist that choice; a missing desktop service
must not silently create a plaintext copy or a second identity namespace. Headless
users can deliberately select the file provider or provision a Secret Service.
Neither root nor another unrestricted same-UID host process is isolated by 0600.

For every provider, project only the selected identity as 0600 Session data;
never grant the target the store, D-Bus address/FD, lock directory, or all of home.
Reject overlapping path/runtime grants and aliases to provider or supervisor
state before materialization; a private mode alone cannot exclude the same UID.
Codex must retain file-only Session auth, no global `~/.codex/auth.json`/OS-store
fallback (`docs/reference/security-model.md:64-84`). Devin's allowlisted source is
`.local/share/devin/credentials.toml` (`internal/adapter/devin/adapter.go:32`);
verify Linux/XDG behavior for the exact admitted target, without broadening copy.

## 6. Devin, Codex and executable paths

Both upstreams distribute Linux CLIs, but upstream availability is not ACS
certification. Install them separately; ACS should keep resolving/pinning target
binaries and checking reviewed versions before contained execution.

| Target | Verified distribution evidence | Paths and qualification work |
| --- | --- | --- |
| Devin | Official docs list Linux; the installer maps x86_64 to `x86_64-unknown-linux`, aarch64 to `aarch64-unknown-linux`. | Installer exposes `~/.local/bin/devin`, backed by `$XDG_DATA_HOME/devin/cli/_versions/<version>/bin/devin` (default `~/.local/share/...`). Pin the resolved executable and required bundle files. |
| Codex | Official docs support Linux. The 0.156.0 release lists `codex-{x86_64,aarch64}-unknown-linux-musl.tar.gz` and matching `codex-code-mode-host-*` archives. | A verified direct install can place `codex` and sibling `codex-code-mode-host` in `~/.local/bin`; package installations may use resource directories. Do not assume a universal install prefix. |

Sources: [Devin docs][devin-docs], [installer:34-38,130-134,197-225][devin-installer],
[Codex docs][codex-docs], [0.156.0 release assets][codex-assets]. Asset listings
were inspected; binaries were not downloaded/executed. Devin's installer mapping
does not prove that ACS's currently pinned 3000.10.21 has both Linux bundles;
obtain version-specific manifests/checksums before adding those lock rows.

Current locks cover only darwin/arm64 (`scripts/devin-test-targets.lock:2`,
`scripts/codex-test-targets.lock:2-5`). Both installers assume that host
(`scripts/install-devin-test-target.sh:19-27`,
`scripts/install-codex-test-target.sh:28-60`). Extend fetching, digest checks,
archive-member validation and CLI/companion pairing per OS/arch/version.

Keep the reviewed Codex set 0.149.1/0.156.0; verify Linux availability and behavior
for each before admitting it. 0.160.0 is explicitly unsupported
(`docs/reference/target-compatibility.md:5-27,49-53`). Linux does not justify
accepting arbitrary versions or removing fixed config/plugin restrictions.
Companion resolution and snapshot validation already exist in
`internal/executor/codex_auth_executable.go:91-148,237,307`.
Review ELF interpreter/libraries, trust roots, DNS/NSS, locale and terminfo inputs
without simply exposing all `/usr` or the real home. Headless login must use the
reviewed target's supported flow; do not expose the desktop bus to launch a browser.

## 7. CI and adversarial evidence

First promote Ubuntu compilation to a required portable job, then add separate
native Linux gates. Use `ubuntu-24.04`, not a floating latest label. The runner
image inventory currently reports an Azure 6.17 kernel, but it is mutable and is
not proof that Landlock is active or usable.[runner-image] Ubuntu 24.04 GA's 6.8
kernel only supplies ABI 4; distribution name alone cannot satisfy ABI 6.
[ubuntu-release][landlock-68]

Record sanitized kernel/architecture, Landlock ABI/errata availability, seccomp,
user/mount/PID namespace probes, AppArmor status and cgroup delegation. Test an
actual denied operation with an allowed positive control. Required native jobs
fail when prerequisites disappear; local optional tests may skip explicitly.
Never count an entire skipped native suite as a passing platform qualification.

Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor. Even rootless
namespace creation can fail or lack setup permissions. Qualify the installed
system bwrap/profile; a custom launcher may need a narrowly scoped admin-supplied
profile. Document that prerequisite and test both allowed and denied hosts.
Do not disable `kernel.apparmor_restrict_unprivileged_userns` globally to make the
CI result green.[ubuntu-userns][ubuntu-apparmor]

Port the following named tests by behavior, with real Linux backends and synthetic
secrets/PTYs. Parameterize portable assertions; retain OS-specific implementation
tests. Existing macOS names remain evidence pointers, not Linux coverage.

| Existing test(s) | Source | Linux acceptance |
| --- | --- | --- |
| `TestSeatbeltPolicyIsDefaultDenyAndUsesParametersForValidatedPaths`; `TestSeatbeltContainsFilesystemNetworkEnvironmentAndDescendants` | `internal/launch/seatbelt_darwin_test.go:62,2770` | Host canaries denied; selected RO/RW grants, clean env, inheritance and positive controls work. |
| `TestPromotedArtifactNativeFilesystemExclusions`; `TestPromotedArtifactNativeFilesystemExclusionCatalogs` | `acceptance/filesystem_exclusions_native_test.go:57,157` | Existing/absent exclusions, rename/unlink/truncate, aliases, hard-link documented limits, and target catalogs retain semantics. |
| `TestSeatbeltVerifiesHostAutomationIsDenied`; `TestSeatbeltVerifiesInboundConnectionsAreNotAccepted` | `internal/launch/seatbelt_denials_darwin_test.go:72,177` | Replace Apple automation with D-Bus/agent/container sockets; test filesystem and abstract AF_UNIX plus loopback bind/listen/connect. |
| `TestSeatbeltNativeRestrictsTerminalAccessToInheritedPTYs`; `TestSeatbeltNativeRetainsControllingTTYWithRedirectedStdio` | `internal/launch/seatbelt_terminal_native_darwin_test.go:31,98` | Deny unrelated PTYs, allow owned devpts; verify redirect semantics, input, resize and signals. |
| `TestSeatbeltReportsTerminalInputQueueAfterTargetExit`; `TestSeatbeltTerminalRestoreDiscardsPendingInput` | `internal/launch/seatbelt_denials_darwin_test.go:254`; `internal/launch/seatbelt_terminal_restore_darwin_test.go:28` | Assert TIOCSTI denial and empty restored input; Linux release gate must not skip this requirement. |
| `TestSeatbeltCleansDescendantAfterProcessGroupAndSessionEscape`; `TestSeatbeltConvergesAcrossForkingAndZombieDescendants` | `internal/launch/seatbelt_darwin_test.go:494,2487` | Double-fork/setsid/fork stress cannot escape cgroup; PID reuse cannot cause unrelated kills. |
| `TestSeatbeltReportsDetachedDescendantAfterSupervisorLoss`; `TestSeatbeltRejectsMalformedMissingAndSpoofedCleanupProof` | `internal/launch/seatbelt_denials_darwin_test.go:223`; `internal/launch/seatbelt_darwin_test.go:741` | Kill outer owner, inner supervisor and PID 1 separately; clean or retain, never forge successful cleanup. |
| `TestSeatbeltTargetCannotInheritOrSpoofControlDescriptor`; `TestSelectedEnvironmentStaysSeparateFromPolicyValidationAndStatusProxy` | `internal/launch/seatbelt_darwin_test.go:2195,1457` | No extra FDs, proof/secret bytes in argv, target control frames, or `/proc` access to trusted processes. |
| `TestAwaitRetainedSessionCleanupFailsFastWhenCleanupIsUnproven`; `TestSeatbeltQuarantineCompletionPreservesSessionLease` | `internal/launch/session_test.go:374`; `internal/launch/seatbelt_darwin_test.go:2674` | Preserve lease/identity through timeout, cancellation, owner loss and recovery. |
| `TestNativeInstalledTargetContainedStatusWithoutCredentials`; `TestCodexPublicProductionMCPProtection` | `internal/executor/codex_auth_installed_target_native_darwin_test.go:23`; `internal/codexauthresource/codex_protection_native_darwin_test.go:168` | Exact installed Linux target, fake identity and isolated provider; no global auth or mutable MCP recipe fallback. |
| `TestPromotedArtifactNativeContainmentContract`; `TestPromotedArtifactSharedTargetConformance` | `acceptance/promoted_artifact_native_test.go:180,2514` | Exercise exact installed candidate bytes for shell, generic commands, Devin and each admitted Codex version. |

Also cover provider absence/lock errors, refresh identity substitution, duplicate
records, forged markers, read-only store, unsafe XDG parents and abrupt power-loss
recovery semantics. Run race tests for shared Go state; keep native process/TTY
tests separate where instrumentation changes behavior. Existing macOS job wiring
is `.github/workflows/macos.yml:95-106`; portable compilation guidance is
`docs/development/testing.md:25-31` (compile-only means `go test -c`, not `-run '^$'`).

Native amd64 and arm64 evidence must precede support for both architectures.
Cross-compilation/QEMU smoke does not prove kernel, signal or terminal behavior.
Use a qualified native arm64 runner, or keep arm64 unpublished pending that gate.

## 8. Release artifacts and documentation

GoReleaser v2 configuration builds `darwin/arm64` with `CGO_ENABLED=0`, checksums,
and deterministic archive metadata; publication is separate
(`.goreleaser.yaml:1-59`, `scripts/release-candidate.sh:26`). Add explicit Linux
amd64/arm64 builds or exclusions so adding amd64 never re-enables Intel macOS.

Proposed public set: `acs_VERSION_darwin_arm64.tar.gz`,
`acs_VERSION_linux_amd64.tar.gz`, `acs_VERSION_linux_arm64.tar.gz`, `SHA256SUMS`,
and `install.sh`. Update exact-set validators together:
`tools/releaseverify/main.go:51-55`,
`internal/release/publication/plan.go:171-177`,
`scripts/install.sh.tmpl:155-168`, `scripts/validate-promoted-artifact.sh:38-52`,
`internal/selfupdate/update.go:111-139`, their tests, and publication scripts.

Keep build-once promotion: `.github/workflows/release.yml:54-79,85-104,234-258`
already transfers candidate bytes to native tests, then attests the archives and
manifest. Expand release and `.github/workflows/promoted-artifacts.yml` matrices
before publishing Linux. The installer is byte-matched but is not currently an
attestation subject (`docs/reference/security-model.md:129-132`). Retain that
precise statement unless separately changing the attestation contract.

Extend source vulnerability scans beyond the hardcoded darwin/arm64 configuration
(`scripts/check-go-vulnerabilities.sh:78-80`), and scan each exact installed Linux
candidate. Lock third-party bwrap/target inputs independently of ACS attestations.
No platform support announcement based solely on successful cross-compilation.

At release, update `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/README.md`,
`docs/development/{architecture,testing,releasing}.md`, and new release notes.
Update `docs/reference/{security-model,target-compatibility,shared-target-conformance,common-profile-format,cli}.md`
and `docs/guides/{getting-started,troubleshooting,diagnostics,session-operations,codex,generic-run,manual-upgrade-recovery}.md`.
Cover kernel/features/distro qualification, provider choice/headless setup, shell,
XDG paths, native evidence, unsupported containers/WSL, and recovery. Change CLI
help and documentation contract tests with the behavior. Preserve historical
release notes; they describe the old matrix, not present support.

## 9. Phased roadmap: small PR stacks

Each PR must preserve macOS gates. Until the final activation PR, production
Linux launch admission remains closed; test-only backend construction must not
be reachable via a user bypass flag. Dependencies below use PR numbers in this
proposal, not GitHub issue numbers. Split implementation further if review grows.

### Stack 1 — foundations

1. **Document the Linux security and delivery contract.** Scope: this document
   only. Depends: none. Accept: cited history/code and reviewed open decisions;
   no product/support claim changes.
2. **Make platform seams explicit without enabling Linux execution.** Scope:
   preserve `ProcessSandbox`, isolate platform authority/shell/provider selection,
   fix only Linux build/vet blockers and build tags found by actual compilation.
   Depends: 1. Accept: `GOOS=linux GOARCH=amd64 go build ./...` and arm64 equivalent;
   `GOOS=linux go vet ./...`; macOS checks unchanged; every Linux execution path
   returns a clear `unsupported on Linux yet` error before target launch, with the
   existing no-unsandboxed-fallback notice. Informational/Profile commands remain
   usable; no claim that all such commands are read-only.
3. **Require Ubuntu portable tests.** Scope: replace nonblocking compile-only job
   with build/vet and audited portable package tests on `ubuntu-24.04`; keep native
   tests distinct. Depends: 2. Accept: job is blocking, executes portable tests
   rather than only compiling them, and exercises unsupported launch/readiness
   behavior without target execution or native-feature assumptions.

### Stack 2 — sandbox backend

4. **Probe Linux capabilities and validate backend provenance.** Scope: Linux
   feature results, sanitized diagnostics, trusted bwrap identity, and mocked
   failure cases. Depends: 3 and maintainer floor/technology decisions. Accept:
   disabled/old Landlock, namespace denial and failed seccomp probes fail closed;
   no unsupported host admitted and no secret-bearing output.
5. **Compile Linux filesystem and runtime authority.** Scope: pure mount/Landlock
   plan compilation; resolve the exclusions/socket-in-grant gates. Depends: 4.
   Accept: RO/RW, protected MCP/auth paths, absent exclusions and ancestor guards
   have demonstrated enforceable semantics; ambiguous plans are rejected.
   The [initial pure compiler](linux-filesystem-plan.md) records its supported
   subset, conservative rejection gates, and outstanding native proof; it does
   not enable production launches.
6. **Implement the sealed Linux launcher.** Scope: trusted namespace setup,
   single-threaded restriction/exec boundary, seccomp, private env/FD transport,
   terminal policy. Depends: 5. Accept: real allowed/denied controls pass under a
   test-only harness; all setup failures start zero untrusted processes; production
   Linux remains disabled until containment integration.
   The [initial sealed launcher](linux-sealed-launcher.md) records primitive
   native evidence, the separate composition gate and remaining limitations.

### Stack 3 — supervisor and containment

7. **Own per-Session Linux process containment.** Scope: delegated cgroups,
   pidfds, PID init/subreaper, gated start, signals and exit status. Depends: 6.
   Accept: fork/setsid/owner-loss tests cannot escape membership or kill unrelated
   processes; missing delegation rejects launch; no leaked resources on abort.
   The [initial containment supervisor](linux-session-containment.md) records the
   gated pidfd/cgroup lifecycle, primitive evidence, and outstanding native
   composition qualification; production Linux remains disabled.
8. **Integrate authenticated Linux cleanup and recovery.** Scope: durable proof,
   lease/quarantine lifecycle, timeout/cancel and TTY restore. Depends: 7. Accept:
   empty-cgroup/reaping proof precedes deletion, lost proof retains state, stale
   generation is rejected, and pending TTY input cannot reach the resumed shell.
   The [initial cleanup and recovery implementation](linux-cleanup-recovery.md)
   records authenticated generation binding, quarantine and terminal restoration;
   production Linux admission remains closed pending full native qualification.

### Stack 4 — credentials

9. **Select credential providers without changing identity semantics.** Scope:
   provider factory, explicit durable choice and provider conformance fixtures.
   Depends: 3; production integration waits for 8. Accept: unavailable provider
   fails closed, no Keychain regression and no silent plaintext fallback.
10. **Implement the chosen Linux credential provider.** Scope: one selected
    provider per PR; file/XDG hardening or Secret Service, then the optional second
    provider in a follow-up. Depends: 9,8. Accept: atomic identity operations,
    headless behavior, refresh/quarantine and absence-of-leak native tests pass.

### Stack 5 — targets

11. **Qualify Linux shell and generic command recipes.** Scope: fixed shell,
    ELF/runtime inputs and diagnostics/help. Depends: 8. Accept: clean startup,
    literal argv, RO defaults, interactive and redirected terminal behavior pass.
12. **Lock and qualify Linux Devin.** Scope: manifest/digest rows, target installer,
    bundle dependencies, exact credential/Skills/MCP preflights. Depends: 11.
    Accept: both planned architectures have verified bytes and native conformance;
    no broader host credential copy or PATH-based backend trust.
13. **Lock and qualify Linux Codex pairs.** Scope: exact reviewed CLI/companion
    pairs, provider projection and fixed execution recipe. Depends: 10,11.
    Accept: each admitted version passes synthetic login/status/interactive,
    refresh, MCP protection and quarantine; no global auth fallback.

### Stack 6 — native adversarial CI

14. **Require native Linux containment and denial gates.** Scope: the parity
    matrix above, kernel/feature evidence and isolated provider fixtures.
    Depends: 8,10,12,13. Accept: amd64 gates fail on missing prerequisites,
    skipped required assertions or leaked resources; normal/race suites retain
    separate evidence; macOS gates continue passing.
15. **Qualify native arm64 and minimum-feature hosts.** Scope: arm64 runner plus
    older/disabled-feature negative matrix and supported filesystem variants.
    Depends: 14. Accept: native arm64 passes the same contract; otherwise defer
    arm64 publication explicitly, and do not substitute emulator evidence.

### Stack 7 — release and docs

16. **Stage Linux candidate artifacts and exact-byte promotion.** Scope: build
    matrix, installer/updater, exact-set validators, scans and attestations; stage
    candidates without publishing a Linux support claim. Depends: 14,15 for
    both architectures. Accept: exact supplied bytes pass every native gate;
    wrong arch, altered archive/manifest and incomplete sets are rejected.
17. **Enable qualified Linux support and publish its contract.** Scope: final
    admission switch, help/docs/security support table, release notes and evidence.
    Depends: 16 and resolution of all security gates. Accept: only qualified
    hosts launch; prerequisites/provider errors are actionable; installation,
    update and recovery examples are checked; release approval uses the existing
    maintainer workflow. This research task does not authorize publication.

## 10. Decisions needed from the maintainer

1. **Sandbox composition:** approve system Bubblewrap + Landlock + seccomp, or
   fund a dedicated launcher. Decide how absent exclusions and pathname sockets
   inside grants are enforced before committing to a kernel floor.
2. **Minimum host:** accept proposed ABI 6/Linux 6.12+ plus tested delegation and
   AppArmor prerequisites, or require ABI 9 for socket mediation. Start with one
   certified Ubuntu/kernel combination; distinguish GA 6.8 from qualified HWE
   hosts. Decide whether non-systemd, WSL and containers are explicitly excluded.
3. **Credentials:** desktop Secret Service first, explicit file provider first,
   or both; choose libsecret/CGO versus reviewed D-Bus implementation. Confirm
   plaintext-at-rest disclosure and Linux XDG paths without moving existing state.
4. **arm64 evidence:** select/budget native hosted or self-hosted arm64 CI;
   otherwise ship amd64 first with arm64 unsupported, adjusting the artifact set.
5. **Process lifetime:** require delegation for all launches initially, including
   SSH/headless hosts; decide how to provision it and recover after reboot without
   treating missing cgroup state as proof.

## External and historical references

[history-033]: https://github.com/alcimerio/ai-config-selector/blob/v0.3.3/docs/releases/v0.3.3.md#L47
[history-040]: https://github.com/alcimerio/ai-config-selector/blob/v0.4.0/docs/releases/v0.4.0.md#L43
[history-checklist]: https://github.com/alcimerio/ai-config-selector/blob/v0.4.0/docs/releases/v0.4.0-checklist.md#L19
[history-removal]: https://github.com/alcimerio/ai-config-selector/commit/786e8193e5493416e806f9db04cdaf3ca7d8c0af
[landlock-abi]: https://landlock.io/rust-landlock/landlock/enum.ABI.html
[landlock-612]: https://docs.kernel.org/6.12/userspace-api/landlock.html
[landlock-current]: https://docs.kernel.org/userspace-api/landlock.html
[seccomp]: https://docs.kernel.org/userspace-api/seccomp_filter.html
[userns]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
[bubblewrap]: https://github.com/containers/bubblewrap#sandboxing
[tty]: https://man7.org/linux/man-pages/man2/ioctl_tty.2.html
[cgroups]: https://docs.kernel.org/admin-guide/cgroup-v2.html
[cgroup-kill-514]: https://www.kernel.org/doc/html/v5.14/admin-guide/cgroup-v2.html
[delegation]: https://systemd.io/CGROUP_DELEGATION/
[pidfd]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html
[subreaper]: https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
[pidns]: https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[secret-service]: https://specifications.freedesktop.org/secret-service/latest/
[libsecret]: https://gnome.pages.gitlab.gnome.org/libsecret/class.Service.html
[xdg]: https://specifications.freedesktop.org/basedir/latest/
[devin-docs]: https://docs.devin.ai/work-with-devin/devin-cli
[devin-installer]: https://cli.devin.ai/install.sh
[codex-docs]: https://learn.chatgpt.com/docs/codex/cli
[codex-assets]: https://github.com/openai/codex/releases/expanded_assets/rust-v0.156.0
[runner-image]: https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md
[ubuntu-userns]: https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts
[ubuntu-apparmor]: https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/
[ubuntu-release]: https://discourse.ubuntu.com/t/ubuntu-24-04-lts-noble-numbat-release-notes/39890
[landlock-68]: https://docs.kernel.org/6.8/userspace-api/landlock.html

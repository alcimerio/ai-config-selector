# Architecture

[Documentation index](../README.md) · [Security model](../reference/security-model.md)

ACS resolves a persisted Profile into an immutable authority plan, materializes
selected content in an ephemeral Session, and runs a registered target or an
explicit command through a required native process sandbox. The supported
runtime is macOS 26 on Apple Silicon (`darwin/arm64`), using the verified system
Seatbelt backend. Unsupported hosts have no sandbox backend and fail closed.

## Domain model

- Profile: stored capability selections. Version 3 separates independently
  versioned common capabilities from explicit target overlays; legacy v1/v2
  Profiles retain their Devin binding and category payloads.
- Category: owns selection schema, discovery, resolution, planning,
  materialization, and optional target verification.
- Resolved authority plan: ordered contributions, runtime grants, and fixed
  target requirements resolved before a Session exists.
- Session: a leased root under `~/.acs/sessions` with mode-0700 synthetic
  home and temporary directories, materialized content, and cleanup state.
- Process sandbox: validates platform and paths, prepares containment and a
  clean environment, and supplies process-tree cleanup proof.
- Execution recipe: registered Devin or Codex, fixed `/bin/zsh -f`, or the
  literal executable and argv supplied to `acs run`.

See the [common Profile format](../reference/common-profile-format.md) for schemas and
[effective capability explanation](../guides/diagnostics.md#effective-capability-explanation) for the
plan's public inspection commands.

## Module boundaries

| Package | Responsibility |
| --- | --- |
| `internal/cli` | Public grammar, Profile loading, terminal streams, exit codes, and composition of planners and launchers |
| `internal/category` | Registry and ordered contribution protocol |
| `internal/commonprofile` | Common capability codecs, defaults, and materialization |
| `internal/authority` | Immutable semantic authority plan and digest |
| `internal/adapter/devin`, `internal/adapter/codex` | Target discovery, Profile editing, projections, and declarative launch requirements |
| `internal/runcommand`, `internal/genericrun` | Resolve literal command identity and argv, then submit them to the shared executor |
| `internal/sandboxshell` | Fixed `/bin/zsh -f` request facade |
| `internal/session` | Target-independent Session creation, leasing, retention, and removal |
| `internal/profilerepo` | Conditional Profile persistence, history publication, and transaction recovery |
| `internal/executor` | Required sandbox selection, target preflights, credentials projection, process attachment, and cleanup ordering |
| `internal/codexauth` | Public named-authentication configuration and typed API facade |
| `internal/codexauthresource` | Credential validation, Keychain access, locks, marker generations, and secure projection/readback |
| `internal/launch` | Platform/path/environment validation, Seatbelt policy, signals, terminal handling, descendant settlement, and sanitized failures |

Adapters declare requirements. The executor selects the backend, manages
process handles and Session leases, and applies the cleanup policy. The
authentication resource package imports neither executor nor Session/process
packages. The executor acquires its authority through typed operations and owns
all process work. Credential projection is separate from generic Profile materialization.

## Command flows

### Planning and dry run

Devin and sandbox-shell dry runs resolve selected material without leasing a
Session or starting the requested target. They may execute the bounded native
readiness probe; unlike
[passive diagnostics](../guides/diagnostics.md#passive-diagnostics), they are
not strictly process-free.

Devin's plan includes inherited repository-local Skills. The generic shell
plan reports only materialized common content. Codex dry-run is syntax-only:
it loads the Profile and explains registered authority without source
discovery, authentication access, executable probes, sandbox checks, or Session
allocation. Identity existence and status remain unchecked.

### Devin

1. Capture termination and resize signals, then validate the native backend,
   executable, workspace, Session root, and runtime inputs.
2. Create and materialize a Session, compile selected local MCP references, and
   copy only the allowlisted `.local/share/devin/credentials.toml`, if present.
3. Run contained `skills list --json` and `auth status`; selected instructions
   also require `rules list` and `rules show` observations.
4. Attach the fixed interactive invocation after the preflights and their
   cleanup complete. Selected environment values go only to the attached
   target and its descendants, not the probes.
5. Preserve terminal streams, signals, resize events, and ordinary exit status;
   settle descendants before removing the Session.

Interactive Devin uses `--respect-workspace-trust false` because the ephemeral
Session cannot retain a workspace-trust decision. The ACS outer sandbox remains
mandatory. The signal-supervisor handoff is reserved before interactive process
preparation: a pending termination prevents launch, while a later termination
is replayed after Start and cannot be replaced by a resize notification.
`VerifyDevin` uses the same protected preflight path for the opt-in
[authenticated smoke](testing.md#optional-authenticated-smoke), without exposing a Session
or process to its caller.

### Interactive Codex and named authentication

1. Resolve the supported overlay and one effective authRef; `--auth` overrides
   the stored reference for this run.
2. Acquire that named resource before executable verification or Session work,
   then take an immutable executable snapshot.
3. Create and protect a private Session with a generation-bound marker.
   Project the selected file credentials before materializing common content
   and Codex projections.
4. Force the registered identity/workspace, provider, endpoint, project-trust,
   and plugin restrictions. Codex uses externally sandboxed no-prompt mode;
   ACS enforces the resolved workspace and other OS grants.
5. Verify exact reviewed CLI version, then attach interactive Codex through the
   shared process executor.
6. Prove cleanup, validate eligible same-identity refreshes, and remove the
   Session before marker deletion and identity release. Uncertain cleanup
   retains the protected Session and identity for recovery.

Login is Create-only. Status and successful execution can replace only a valid
changed projection with the same identity metadata; recovery never turns an
interrupted login into a credential record. See
[named Codex authentication](../guides/codex.md#named-authentication) and
[interactive Codex](../guides/codex.md#interactive-launch) for the operator
contract.

### Sandbox shell and generic commands

Both paths validate containment, create and materialize a generic Session, and
use the shared attached-process lifecycle. Neither selects a target overlay,
projects target authentication, or runs Devin preflights. Explicit common
environment selections may still include secrets.

The shell always runs `/bin/zsh -f`, ignoring `$SHELL` and startup files.
`RunCommand` accepts only a resolved literal executable and argv plus the
common authority plan. It revalidates executable identity after materialization
and immediately before native preparation; it adds no inferred authority.
See [generic commands](../guides/generic-run.md) for usage and argv semantics.

## Filesystem and environment policy

Seatbelt starts with `deny default` and validated canonical path parameters.
The generated policy grants:

- workspace reads, with writes only when selected (new v3 Profiles default to
  read-only; legacy v1/v2 remain writable);
- private Session reads and writes, except protected configuration;
- explicitly selected path access and executable visibility;
- minimal macOS runtime, fixed commands, and declared read-only runtime inputs;
- process creation, same-sandbox process information/signals, and the invoking
  pseudo-terminal and descriptors;
- coarse outbound IP, mDNS resolution, and required platform TLS trust services.

The environment is reconstructed with synthetic `HOME`, XDG and temporary paths,
a fixed `/usr/local/bin:/usr/bin:/bin` `PATH`, and a small terminal/locale
allowlist. Arbitrary host variables and inherited file descriptors are absent.
Explicit `common.environment` values are resolved into a sealed lease before
Session creation and transferred over the private bounded supervisor channel
after policy validation. The supervisor constructs the attached target's final
environment immediately before start. Validation, status, authentication, and
version probes remain value-free.

Selected values transit trusted supervisor memory and are readable by the
attached process tree, including local MCP servers. Codex shell snapshots are
disabled when environment values are selected, avoiding their serialization
into snapshot files. Unsupported hosts fail closed before Session creation.

Unrelated host paths and Unix sockets remain denied. Directory grants cover
their descendants; see
[path grants and pathname-race limits](../reference/common-profile-format.md#explicit-filesystem-paths).
ACS is not an egress firewall and does not create independent per-tool,
per-MCP-server, or per-agent authority boundaries. Selecting a plugin, hook, or
agent definition as readable data does not activate it as a Profile capability;
Codex plugins are disabled in the registered production recipe.

## Lifecycle and cleanup

Every prepared process is retained by its Session before Start. A failed Start
is not waited; a successful Start is waited exactly once. Wait returning does
not prove that descendants have exited. Each probe and its descendants must exit
before its result can authorize the next probe or attached target.

The macOS backend supervises a process group and uses a private protocol for
signals and authenticated cleanup proof. Normal completion, nonzero exit,
signals, cancellation, startup failure, and surviving descendants follow the
same lease rule. Cleanup uncertainty or finalization failure takes precedence
over an ordinary target exit and retains or quarantines ownership until
settlement is proven.

Startup cleanup respects file-lock leases held by other ACS processes. An
unlocked lease alone is insufficient to reclaim a previously prepared Session:
its matching native cleanup proof is also required. Removal is logical cleanup,
not physical erasure. See
[Session inspection and recovery](../guides/session-operations.md) for the
operator-visible states and recovery procedure.

The backend requires the root-owned, non-writable system `/usr/bin/sandbox-exec`
to pass a fixed capability probe and validates generated policy before launch.
It reports stable sanitized failure categories; there is no backend selector or
unsandboxed fallback.

## Persistence and compatibility

Profiles use mode-0600 files in mode-0700 directories under `~/.acs/profiles`.
Creation is atomic and refuses replacement. Legacy v1 Profiles are normalized
in memory without rewriting their files; migration to v3 is explicit. Capability
schemas evolve independently, and unsupported selected schemas fail resolution.

[Portable exchange](../guides/portable-profile-exchange.md) is a separate versioned codec.
It exports stored v3 intent with symbolic machine-local source, authentication,
path, executable, and secret-environment bindings, never a resolved authority
plan or raw local JSON. Passive validation does not discover sources, access
credentials, create Sessions, or run targets. Complete explicit bindings produce
one immutable candidate for conditional Profile creation; export file output
uses exclusive no-replace creation.

## Profile repository transactions

`internal/profilerepo` stores bounded opaque canonical documents; Profile codecs
remain above that boundary. Revisions bind the exact name, presence and bytes. A
mismatch rejects a stale write. Changes that return to the same bytes are not
detected as historical changes. Create, clone, and rename require an absent
destination; replace and delete require the observed source revision. Rename can
briefly expose both names and is not a two-name atomic snapshot.

Mutations and recovery share one stationary file lock. Under that ownership,
ACS settles any previous transaction before rechecking the new request's
conditions. Reads, Profile inspection, and diagnostics never lock, bootstrap,
or recover the repository. Descriptor-relative no-follow operations, private
file modes, bounded records, and object-identity checks reject observed unsafe
state. Advisory locking excludes cooperating writers, not arbitrary same-user
filesystem interference; do not remove a lock to bypass contention.

The recoverable transaction has three boundaries:

1. Prepare and synchronize desired bytes and the exact bound history record
   before publishing the immutable decision.
2. After the decision, publish the Profile/history pair and synchronize the
   namespace. Recovery rolls forward; it does not silently restore old bytes.
3. Synchronize the terminal receipt, then retire private artifacts. Malformed,
   unknown, or inconsistent evidence is preserved and blocks unsafe mutation.

Before a decision, recovery aborts private preparation. History snapshots and
lineage are part of the decided transaction, not a later best-effort append.
Explicit history restore is a new conditional mutation. Clone creates a new
lineage; rename preserves it. See [Profile history](../guides/profile-history.md) for
retention, pins, and restore behavior.

Outcomes separate `NotCommitted`, `Committed`, or `Unknown` from
`RecoveryRequired`. Pre-decision rejection is not committed; uncertainty once a
decision can exist requires recovery. A synchronized terminal receipt establishes
commit even if later cleanup reports an error. Cancellation after the decision
does not skip settlement. A lost response is not permission for a blind retry,
and completed cleanup does not provide an exactly-once guarantee for later retries.

The durability guarantee is checked file/namespace synchronization and
process-interruption recovery on the tested filesystem. Successful sync calls
and process-kill tests do not prove hardware power-loss behavior or all volume
configurations. Synchronization errors never become success. See the
[repository implementation and regression tests](../../internal/profilerepo),
[Profile commands](../guides/profiles.md), and [manual recovery](../guides/manual-upgrade-recovery.md).

For native checks and artifact verification, see [testing](testing.md) and
[releasing](releasing.md).

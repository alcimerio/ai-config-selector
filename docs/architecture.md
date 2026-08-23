# Architecture

ACS resolves a persisted Profile into ordered contributions, materializes those
contributions into an ephemeral Session, and starts one fixed target through a
required native process sandbox.

## Supported runtime

The v0.4.0 runtime and release matrix is:

| OS | Architecture | Native backend |
| --- | --- | --- |
| macOS 26 | `darwin/arm64` | verified system Seatbelt |
| macOS 26 | `darwin/amd64` | verified system Seatbelt |

Linux and Bubblewrap code remains in the repository but is unsupported. v0.3.3
is the final Linux release. v0.4.0 does not produce Linux assets or run Linux
native release gates. A non-blocking compile observation is retained to expose
obvious portability breakage without turning it into a support promise.

## Domain model

- **Profile**: a named persisted selection for one target. The envelope has a
  version, target, and category-owned payloads.
- **Category**: owns selection schema, discovery, resolution, planning,
  materialization, and optional target verification.
- **Resolved Profile**: ordered immutable contributions produced before any
  Session exists.
- **Session**: a leased ephemeral root containing synthetic `home` and `tmp`
  directories and materialized Profile content.
- **Process Sandbox**: validates platform and paths, creates a clean environment,
  prepares a native contained process, and reports bounded cleanup proof.
- **Target**: Devin or the fixed credential-free sandbox shell.

## Module boundaries

`internal/cli` owns public grammar, Profile loading, terminal streams, and exit
codes. It selects a planner and launcher but does not know how Skills,
credentials, Sessions, or Seatbelt work.

`internal/category` owns the registry and ordered contribution protocol. A
contribution can plan, materialize into a Session home, and optionally verify a
target-specific observation.

`internal/session` owns target-independent Session creation and lifecycle. It
leases a unique root under `~/.acs/sessions`, creates mode-0700 synthetic home
and temporary directories, asks the resolved Profile to materialize, retains
the lease while a prepared process may still have descendants, and removes the
root only after cleanup settles.

`internal/adapter/devin` owns Devin discovery, Profile editing, its allowlisted
credential, Skill catalog verification, authentication preflight, and Devin
launch semantics. Interactive launches pass `--respect-workspace-trust false`:
the ephemeral Session cannot retain a workspace-trust decision, while the ACS
Process Sandbox remains the mandatory boundary. Credential copying happens
after generic Session creation; it is not part of Profile materialization.

`internal/sandboxshell` owns the fixed `/bin/zsh -f` target. It creates a generic
Session and never invokes the Devin executable, accesses a Devin credential, or
runs category verification. It uses the same Process Sandbox and Session
lifecycle as Devin.

`internal/launch` owns platform detection, path and environment validation,
Seatbelt policy generation, process preparation, signal forwarding, process-tree
settlement, cleanup quarantine, and stable sanitized failures.

## Command flows

### Dry run

Both dry runs load and strictly resolve a Profile without leasing a Session.

`acs devin --profile NAME --dry-run` reports materialized global Skills,
repository-local Skills inherited specifically by Devin, and sandbox readiness.

`acs sandbox --profile NAME --dry-run` reports only content materialized into
the generic Session plus sandbox-shell readiness. It does not report Devin-only
repository inheritance.

### Devin

1. Validate the supported platform, backend, executable, workspace, Session
   root, and runtime inputs before leasing a Session.
2. Create a generic Session and materialize selected Skills.
3. Copy only the allowlisted Devin credential when present.
4. Verify the observed Skill catalog and authentication inside Seatbelt.
5. Prepare and attach Devin without pass-through options.
6. Preserve terminal streams, signals, resize events, and ordinary exit status.
7. Settle descendants, then remove the Session; quarantine uncertain cleanup.

### Sandbox shell

1. Validate Seatbelt readiness and the fixed `/bin/zsh` executable before
   leasing a Session.
2. Create a generic Session and materialize selected Skills.
3. Prepare `/bin/zsh -f`; no target argument or environment setting can replace
   the executable, enable startup files, or bypass containment.
4. Attach the invoking terminal and preserve signals, resize, and exit status.
5. Settle descendants, then remove the Session; quarantine uncertain cleanup.

## Filesystem and environment policy

Seatbelt begins with `deny default`. Generated parameters contain only validated
canonical paths. The policy grants:

- read/write under the workspace and leased Session;
- read access to the minimal macOS runtime and fixed commands;
- read-only access to explicitly declared runtime inputs;
- process creation, same-sandbox process information and signals;
- the invoking pseudo-terminal and its descriptors;
- outbound IP networking, mDNS resolution, and the exact trust services needed
  for platform TLS.

The target environment is reconstructed. It sets synthetic `HOME`, XDG, and
temporary paths, a fixed `/usr/local/bin:/usr/bin:/bin` `PATH`, and a small
terminal/locale allowlist. Arbitrary host environment variables and inherited
file descriptors are absent.

Unrelated host paths, writes outside workspace/Session, symlink escapes, and
unrelated Unix sockets remain denied. This is process and filesystem isolation,
not network destination control. ACS is not an egress firewall.

## Lifecycle and cleanup

Each Session has a file-lock lease. Startup removes only abandoned Sessions and
does not disturb Sessions held by concurrent ACS processes. A prepared process
retains the lease until its backend cleanup channel proves that the contained
tree is gone.

The macOS backend starts a supervised process group and uses a private control
protocol for signals and cleanup proof. Normal completion, nonzero exit,
signals, cancellation, startup failure, and outliving descendants all converge
on the same lease rule. A bounded failure to prove cleanup returns a stable
failure and keeps asynchronous quarantine ownership until settlement succeeds.

## Fail-closed properties

- Users cannot select a backend or request an unsandboxed launch.
- Unsupported platforms fail before Session creation.
- The Seatbelt executable must be the root-owned, non-writable system
  `/usr/bin/sandbox-exec` and must pass a fixed capability probe.
- Generated policy is validated before the target starts.
- Sensitive backend output and paths are replaced with stable error categories.
- Cleanup failure takes precedence over an ordinary target exit.
- Dry run never creates a Session or starts a target.

## Persistence and compatibility

Profiles live under `~/.acs/profiles` with mode 0600 in mode-0700 directories.
Creation is atomic and refuses replacement. Version-1 Profiles are normalized
in memory without rewriting their files. Category schemas evolve independently
inside the version-2 envelope; unknown categories and unsupported schema
versions fail strict resolution.

v0.4.0 preserves the existing Profile format and Devin command grammar. It adds
`acs sandbox --profile NAME [--dry-run]` and removes Linux from the supported
runtime and artifact matrix.

## Release evidence

The candidate is built once. The exact supplied bytes are installed and tested
on macOS 26 arm64 and Intel. Each native job runs the repository suite, race
suite, and installed-artifact acceptance, including sandbox shell Skills,
credential absence, allowed and denied paths, terminal lifecycle, descendants,
and cleanup. Attestation and immutable publication depend on both native jobs.

The optional authenticated Devin smoke uses local maintainer credentials and is
supplemental. It cannot replace the credential-free native candidate gates.

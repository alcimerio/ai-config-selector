# Codex launch and named authentication

[Documentation index](../README.md)

ACS supports interactive Codex on macOS 26 Apple Silicon with the exact target
versions listed in [target compatibility](../reference/target-compatibility.md).
The adapter uses ChatGPT authentication and a named
ACS identity; API keys, credential import and noninteractive token injection
are unsupported.

## Interactive launch

Create an identity, select a common Profile, then launch:

```sh
acs codex auth login --name work
acs codex create-profile --name backend-review --auth work
acs codex --profile backend-review --dry-run
acs codex --profile backend-review
```

The builder uses the [common format](../reference/common-profile-format.md) and
[revisioned repository](../development/architecture.md#profile-repository-transactions). Its version-1
Codex overlay stores only opaque `authRef`, never credentials or arbitrary
Codex settings. Launch `--auth personal` overrides the reference for one run
without changing the Profile. Creation may omit `--auth`; that Profile requires
`--auth REF` on both dry-run and real launch. Unsupported selected overlays fail
closed and are never silently added.

Dry-run checks stored structure and effective reference syntax only. It does
not discover sources, access Keychain/providers/status, lock identities, probe
executables or sandbox state, allocate Sessions or start processes. Identity
existence and status remain unchecked. A successful dry-run does not prove the
identity exists, Keychain is readable or Codex has the required version.
`acs codex auth status --name work` is a separate contained credential-using
operation, with the refresh rules below.

Real launch holds one effective named identity from before Session creation
until projection removal. The shared executor pins the executable, materializes
common Skills, projects selected copies to
`.codex/skills/<source>/<relativePath>`, projects authentication, checks the exact
version and starts interactive Codex. It owns terminal streams, signals,
resize, cancellation, descendant settlement, cleanup and recovery.

The fixed recipe forces these settings at runtime precedence:

- A private synthetic home, file credential storage, ChatGPT login and any
  bound ChatGPT workspace restriction.
- The official ChatGPT endpoint and OpenAI provider, untrusted project
  configuration, and disabled stock plugin/app features.
- `sandbox_mode="danger-full-access"` and `approval_policy="never"`, the locked
  target's supported externally sandboxed no-prompt mode.

ACS's outer sandbox enforces read-only or coding-write workspace authority and
selected common grants. Codex creates no nested Seatbelt profile or per-tool
approval prompts. Its full target permission remains contained; Codex's own
root model and managed-sandbox messages are not the security boundary. A missing
or uncertain ACS sandbox fails closed, never falling back to direct launch.
There is no generic argument/configuration passthrough, backend selector,
dynamic plugin authority or fallback to another identity.

### Selected material and authority limits

Skill projection preserves source/path identity, modes, relative symlinks and
collision checks without rereading host origins. Repository `.agents/skills`
and bundled system Skills remain Codex-owned: selected-only describes
ACS-managed global projections, not all readable workspace files.

[Instructions](../reference/common-profile-format.md#instruction-bundles) are copied to common
Session material only; ACS does not automatically activate them as Codex
instructions or project Devin rules into Codex. Paths, executables, environment
and [local STDIO MCP references](mcp-profiles.md) retain common semantics.
Isolation, disabled stock features and fixed project trust prevent ordinary
host-local/project-local MCP configuration from becoming launch input. An empty
selected table does not claim to clear every account-service or enterprise
policy source selected by the authenticated account.

The projected authentication file is readable by Codex and its tools and
descendants in the Session. Selected Skills and MCP helpers have no separate
credential-isolation boundary. Coarse outbound IP permits transmission of
readable data; choose the workspace, tools and helpers with that authority in
mind. Profiles contain no credentials or Keychain records, so deleting one
never deletes a named identity.

Successful target-authored credential changes use the identity validation
performed by status. Failed runs, deleted or invalid projections, changed
identity/workspace/method and unknown schemas cannot replace the last valid
record. Target success never overrides uncertain cleanup; settlement,
projection removal, marker deletion and identity release use the recovery
contract below.

## Named authentication

Authentication uses three separate stores:

1. Global Codex authentication lives outside ACS, typically in the real
   `~/.codex/auth.json` or Codex's OS credential-store namespace.
2. ACS durable identity is a validated, versioned record under a name such
   as `work` in macOS Keychain service
   `com.alcimerio.ai-config-selector.codex-auth`.
3. Session-local projection is private `auth.json` owned by one leased
   synthetic home for status or launch, never a shared Codex cache.

ACS never reads, imports, replaces, deletes or falls back to global Codex
authentication. External `codex login`/`logout` and ACS named-auth operations do
not alter each other's records.

```sh
acs codex auth login --name work
acs codex auth login --name work --device-auth
acs codex auth list
acs codex auth status --name work
acs codex auth recover --name work
acs codex auth logout --name work
```

Login defaults to browser-based ChatGPT login; `--device-auth` selects device
login. Names contain 1 to 64 lowercase ASCII letters, numbers, dots, underscores or
hyphens and begin with a letter or number. Existing names fail before Codex
starts; explicitly log out before reusing one. Login requires actual terminal
stdin/stdout; character devices such as `/dev/null` do not qualify. Any version
output outside the exact reviewed set is a compatibility error.

### Contained login and executable identity

Before Session creation or credential projection, ACS resolves, hashes and pins
Codex, copies its bytes into a private read-only operation snapshot outside the
target-writable workspace/Session, and checks native sandbox availability for
the workspace, Session root, snapshot and runtime inputs. A supported installed
`codex-code-mode-host` companion is pinned into that same snapshot. Both version
and credential-bearing subprocesses use the snapshot, so changes to installed
files cannot switch verified bytes. This checks executable identity, not vendor
signatures or distribution checksums for arbitrary local installations.

Codex receives an exact read-only probe for `/etc/codex/requirements.toml` to
honor managed requirements or normal absence without gaining the rest of `/etc`.
Login then:

1. Creates a leased Session/synthetic home, credential-free identity quarantine
   marker and Session recovery protection before credential bytes are written.
2. Writes private `.codex/config.toml` selecting file storage and ChatGPT login,
   and passes matching `-c` overrides so project configuration cannot replace them.
3. Verifies the exact version and runs `codex login` (optionally device-auth)
   inside the mandatory sandbox.
4. Traverses Session root, `home` and `.codex` through private no-follow directory
   descriptors, opens only `auth.json`, and requires a private, regular,
   single-link file owned by the invoking user.
5. Validates bounded JSON and derives non-secret metadata before the first
   durable write, atomically creates the Keychain record, and removes the Session.

Temporary credential bytes are never copied to Profiles, logs, plans, errors or
argv and are never a durable file provider. Removal is logical, not physical
erasure. Uncertain process cleanup makes login fail and leaves the name/Session
quarantined until settlement is proved and recovery removes the projection.

### Keychain record and metadata

Each identity is one generic-password item with fixed ACS service and validated
name as account. Secret data is a versioned validated-credential envelope;
the comment is versioned non-secret metadata: login method (`chatgpt`), optional
ChatGPT workspace/account restriction and a stable SHA-256 identity fingerprint
derived from method, workspace and authenticated user identifier.

`auth list` queries attributes only, without retrieving secrets, printing the
fingerprint or maintaining a second index. Provider loads revalidate credentials
against metadata. Writes request non-synchronizable,
when-unlocked-this-device-only items; all production queries prohibit
authentication UI. Locked/unavailable providers, ambiguous names, malformed
records, unsupported schemas or metadata mismatch fail closed without plaintext
fallback. Restore normal Keychain access and repeat; there is no second index
to repair.

### Contained status and refresh

`auth status` validates/locks the name, revalidates the Keychain record, pins the
Codex executable and checks native sandbox availability before creating a
Session. It durably marks the identity and Session recovery-owned before
writing private configuration/authentication files. File storage, ChatGPT login
and any workspace restriction are applied in config and runtime `-c` overrides;
the process uses synthetic `HOME/.codex/auth.json`, never the user's global home
or an OS-store fallback. ACS checks the exact version, then runs contained
`codex login status`.

After proving process cleanup, ACS validates the final projection, makes one
typed commit-or-discard decision, removes the projection, then releases the
identity lock. Refresh eligibility is durably recorded only after status
succeeds, so crash recovery cannot commit bytes from failed status. A refreshed
payload can atomically replace Keychain only when its schema, login method,
workspace and stable fingerprint match the durable identity. Dispositions are:

- `committed_same_identity_refresh`: a validated refresh replaced the payload.
- `discarded_projection`: unchanged or safely rejected projection removed.
- `quarantined_uncertain`: cleanup or finalization could not be proved.

A missing file, failed status, forced logout, changed identity/workspace/method
or unknown schema is never durable logout. ACS keeps the last valid Keychain
payload and discards rejected projections only after verified cleanup.

## Quarantine and recovery

Keep quarantined Sessions and recovery files intact. Once the earlier operation
is inactive, run `acs codex auth recover --name work`, then retry
`acs codex auth status --name work`. Recovery refuses removal without process
cleanup proof; deleting files or logging out cannot substitute for that proof.
Use the [Session guide](session-operations.md) for passive inspection.

Before projection, ACS writes private credential-free metadata under
`~/.acs/quarantine/codex-auth` and recovery protection in the Session lease
directory. Metadata contains only version, identity name, random Session ID,
lifecycle phase, refresh-eligibility flag when set and a random cleanup-proof
challenge hidden from the target. It contains no credentials, fingerprints,
tokens, workspace identifiers or `auth.json`.

Recovery protection excludes the Session from ordinary abandoned-Session
cleanup. The name stays blocked across ACS processes even after the original
file lock is released. The phases define what can be recovered:

- `prepared`: discard an inactive projection only; no subprocess preparation
  has begun. A crash before Session protection is handled by acquiring the
  inactive lease and discarding without reading/committing projected credentials.
- `cleanup_pending`: immediately before subprocess preparation, ACS durably
  arms challenge-authenticated no-process proof and advances the marker.
  Recovery requires valid proof and an inactive protected lease.
- `recoverable`: after settlement is proved and the live Session guard released,
  ACS atomically advances the marker. Recovery requires an inactive protected
  lease and revalidation against the current durable identity.

The supervisor removes armed proof after receiving its challenge, acknowledges
readiness only after removal, and waits for its owner's explicit start decision.
If the owner disappears there, it durably proves no target started. After target
start, proof is durably synced only after zero live target processes are
established. Proof therefore survives an ACS crash without being forgeable by
the target; an unlocked Session alone is insufficient.

Recovery makes an idempotent decision. It commits only a valid, eligible
refresh for the same identity. It discards missing, unchanged, invalid, deleted
or identity-changing projections. It removes the protected Session before the identity
marker. Active Sessions or pending markers without proof remain blocked. If
cleanup already removed the Session, recovery clears the stale marker as an
already-discarded projection.

If asynchronous settlement publishes `recoverable` while still holding the
identity lock, recovery waits for that exact marker generation's lock handoff.
Cancellation stops waiting; another recovery's removal is idempotent success.
Prepared, pending, malformed or replaced generations remain blocked. All Session
removal is logical, not a physical-erasure claim.

### Concurrency and private-state boundaries

Login, status, launch, recovery and logout acquire a private non-blocking lock
for the selected name. Same-name use returns in-use through projection removal
or quarantine; different names can proceed independently. Atomic Keychain
creation also prevents cross-process duplicate replacement. Logout deletes
only that named ACS record, succeeds if a valid name is already absent, and
refuses quarantined names.

Command/registry metadata remains available when cwd overlaps ACS home, but
contained login/status refuse that workspace before sandbox preflight or Session
creation. ACS anchors home to a canonical parent and opens private lock and
quarantine directories without following symlinks, preventing target redirection
of private state, access to proof challenges or snapshot modification through
workspace permissions.

## Evidence and upstream behavior

See [testing](../development/testing.md#native-named-authentication-evidence)
for credential-free native gates, recovery precautions and supplemental
real-account observations, and [target conformance](../reference/shared-target-conformance.md)
for cross-target behavior. Automated checks do not prove interactive login,
target-origin refresh or sustained daily use.

Codex's [authentication documentation](https://learn.chatgpt.com/docs/auth)
describes browser/device login, status/logout, token refresh,
`$CODEX_HOME/auth.json` and OS-store modes. Its
[managed-configuration documentation](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
defines `/etc/codex/requirements.toml`. ACS uses temporary contained file
storage and owns its separate durable Keychain namespace.

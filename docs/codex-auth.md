# Named Codex authentication and contained status

This document describes the named-authentication management slice present in
the development source. It is not part of the published v0.4.0 release and does
not yet launch an interactive Codex process.

## The three authentication states

Keep these states separate:

1. **Global Codex authentication** belongs to Codex outside ACS. Depending on
   Codex configuration, it can live in the real home at
   `~/.codex/auth.json` or in Codex's OS credential-store namespace.
2. **An ACS durable identity** is one validated, versioned record stored under
   a name such as `work` in the macOS Keychain service
   `com.alcimerio.ai-config-selector.codex-auth`.
3. **A Session-local projection** is a private `auth.json` created for one
   contained status probe. It is owned by one leased synthetic home and never
   becomes a shared Codex cache.

ACS named-auth commands never read, import, replace, delete, or fall back to
global Codex authentication. Consequently, `codex login` or `codex logout`
outside ACS can change the global Codex login without changing an ACS durable
identity. The inverse is also true: ACS logout addresses only the named ACS
record.

## Commands and names

Browser-based ChatGPT login:

```sh
acs codex auth login --name work
```

Explicit device authentication:

```sh
acs codex auth login --name work --device-auth
```

Metadata-only listing, contained status, recovery, and idempotent removal:

```sh
acs codex auth list
acs codex auth status --name work
acs codex auth recover --name work
acs codex auth logout --name work
```

Identity names are canonical lowercase values. They contain 1–64 lowercase
ASCII letters, numbers, dots, underscores, or hyphens and begin with a letter
or number. An existing name causes login to fail before Codex starts; ACS does
not silently replace it. To reuse a name, explicitly log it out first and then
log in again.

Login requires stdin and stdout that are actual terminal endpoints; character
devices such as `/dev/null` are not accepted as interactive. The current
implementation accepts ChatGPT authentication only and pins the exact output
`codex-cli 0.149.1`. API-key, non-interactive token injection, and credential
import are unsupported.

## Contained login and cleanup

Before creating any temporary state, ACS resolves, hashes, and pins one
canonical Codex executable identity, then verifies that its native Process
Sandbox is available for the workspace, Session root, pinned executable, and
runtime inputs. Each operation copies those verified bytes once into a private
read-only snapshot outside the target-writable workspace and Session. Both the
version probe and credential-bearing subprocess execute that same snapshot, so
path replacement and in-place rewriting cannot switch the executable after
verification. Codex also checks the optional
managed-requirements file at
`/etc/codex/requirements.toml`. ACS grants an exact, read-only probe for that
file: Codex can enforce it when present and receives the normal not-found result
when absent, without gaining access to the rest of `/etc`. It then:

1. creates a leased private Session and synthetic home;
2. creates a secret-free identity quarantine marker and recovery-protects the
   Session before credential bytes can be written;
3. writes a private `.codex/config.toml` that selects file credential storage
   and forces the ChatGPT login method;
4. passes the same storage and login-method restrictions as Codex `-c`
   overrides so project configuration cannot replace them;
5. verifies the exact Codex CLI version inside the sandbox;
6. runs `codex login`, optionally with `--device-auth`, inside the same sandbox;
7. walks the Session root, `home`, and `.codex` through private directory
   descriptors without following symlinks, then opens only `auth.json` and
   requires a private, regular, single-link file owned by the invoking user;
8. validates the bounded JSON schema and derives non-secret metadata before the
   first durable write;
9. atomically creates the named Keychain record and removes the temporary
   Session.

The temporary file necessarily contains credential bytes between successful
Codex login and Keychain storage. It is never a durable ACS provider and is not
copied to a Profile, log, plan, error, or command-line argument. Session cleanup
is logical removal; ACS does not claim physical erasure from the filesystem or
storage media. If contained-process cleanup is uncertain, login fails rather
than reporting a stored identity as safely completed, and its name and Session
remain quarantined until settlement is proven and recovery removes the
projection.

## Keychain record and metadata

Each identity uses one generic-password item whose service is fixed to the ACS
namespace and whose account is the validated identity name. Its secret data is
a versioned envelope containing the validated Codex credential. Its comment
attribute contains a versioned, non-secret metadata envelope:

- login method (`chatgpt`);
- optional ChatGPT workspace/account restriction;
- a stable SHA-256 identity fingerprint derived from method, workspace, and
  authenticated user identifier.

The fingerprint is retained for later same-identity refresh validation but is
not printed by `auth list`. Listing queries Keychain attributes only; it does
not retrieve secret data or maintain a second index. Loading a record through
the internal provider revalidates the credential and requires it to match its
metadata.

Keychain operations fail closed if the provider is unavailable or locked, a
name is ambiguous, a record is malformed, the credential schema is unsupported,
or metadata does not match the secret. There is no plaintext-file fallback.
After restoring normal Keychain access, repeat the command; ACS does not leave a
partially created second index to repair.

## Contained status binding

`auth status` uses the same exact Codex version as login. Its lifecycle is:

1. validate the identity name and acquire its non-blocking lock;
2. load and revalidate the selected Keychain record;
3. pin the canonical Codex executable identity and verify native sandbox
   availability before Session creation;
4. create a leased Session plus synthetic `HOME` and durably mark both the
   identity and Session as recovery-owned before writing credential bytes;
5. write private `.codex/config.toml` and `.codex/auth.json` files with file
   credential storage, forced ChatGPT login, and the validated workspace
   restriction when present;
6. pass those restrictions as Codex `-c` overrides, which have runtime
   precedence over project configuration;
7. verify `codex-cli 0.149.1` and run `codex login status` inside the mandatory
   process sandbox;
8. prove contained-process cleanup, validate the final projected credential,
   make one typed commit-or-discard decision, remove the projection, and only
   then release the identity lock.

The generated configuration prevents Codex from falling back to an OS store or
another login method. The process receives the Session's synthetic `HOME`, so
the effective file location is that Session's `HOME/.codex/auth.json`; ACS does
not set the process to the invoking user's global Codex home.

Codex may refresh ChatGPT tokens during status. ACS durably records refresh
eligibility only after `codex login status` succeeds; crash recovery therefore
cannot commit target-authored bytes from a failed status outcome. ACS atomically
replaces the Keychain payload only when the final file remains schema-valid and
its login method, workspace, and stable identity fingerprint equal the durable
record. The terminal dispositions are:

- `committed_same_identity_refresh`: a validated refresh replaced the durable
  payload;
- `discarded_projection`: the projection was unchanged or safely rejected and
  logically removed;
- `quarantined_uncertain`: cleanup or finalization could not be proven.

A missing projected file, failed status, forced logout, changed identity,
changed workspace, changed method, or unrecognized schema is never interpreted
as a durable logout. ACS retains the last valid Keychain payload and discards
the projection after verified cleanup.

## Quarantine and recovery

Before projecting credentials, ACS creates a private, credential-free marker under
`~/.acs/quarantine/codex-auth` and a private recovery-protection marker in the
Session lease directory. Quarantine metadata contains only its version, the
identity name, the random Session identifier, a lifecycle phase, and a random
cleanup-proof challenge that is never exposed to the contained target. It never
contains credential bytes, metadata fingerprints, authentication tokens,
workspace identifiers, or `auth.json`.

Recovery protection prevents normal abandoned-Session cleanup from reclaiming
a quarantined projection. The marker starts in `prepared`, where recovery can
only discard an inactive projection because no subprocess preparation has
begun. Immediately before preparation, ACS durably arms a challenge-authenticated
no-process proof and advances the marker to `cleanup_pending`. After the
original ACS process proves settlement and releases the live Session guard, it
atomically advances the marker to `recoverable`. The name remains blocked
across ACS processes even after the original file lock is released. `auth
recover` acquires that name and revalidates a recoverable or proven pending
projection against the current durable identity. Those phases require an
inactive protected Session lease. A crash after publishing `prepared` but
before recovery protection is handled only through that prepared phase: ACS
acquires the inactive Session lease and discards the projection without reading
or committing it. Recovery then makes one idempotent decision:

- commit a different payload only when it is a valid same-identity refresh; or
- discard missing, unchanged, invalid, deleted, or identity-changing state.

The native supervisor removes the armed proof after receiving its challenge,
acknowledges readiness only after that removal, and waits for an explicit start
decision from its owner before starting the target. If the owner disappears at
that boundary, the supervisor durably proves that no target started. After a
target does start, the supervisor writes and durably syncs the same proof
only after it has established zero live target processes. This ordering lets a
crash before the first process recover from the armed proof without allowing a
live target to reuse it. The evidence survives an ACS crash without being
forgeable by the contained target. Recovery removes the protected Session
before deleting the identity marker. If the Session is still active, or a
`cleanup_pending` marker lacks valid proof, both markers remain and the identity
stays blocked. A pending inactive Session with valid proof can be finalized
safely; an unlocked Session alone is not treated as proof. If prior cleanup
already removed the Session, recovery clears the stale marker as an
already-discarded projection.

When asynchronous settlement has published `recoverable` while it still holds
the identity lock, recovery waits for that exact marker generation to hand off
the lock. Cancellation stops the wait, removal by another recovery is treated
as idempotent success, and prepared, pending, malformed, or replaced generations
remain blocked.

Session removal is logical removal; ACS does not claim physical erasure from
the filesystem or storage media.

## Concurrency and current boundary

Login, status, recovery, and logout acquire a private, non-blocking file lock
for the selected name. Concurrent use of the same identity returns an in-use
error through final projection removal or quarantine; different names can
proceed independently. Keychain creation is also atomic, so a duplicate cannot
replace the existing record even across processes.

Registry and command metadata construction remain available when the current
working directory overlaps ACS home. Contained login and status refuse that
workspace before sandbox preflight or Session creation, where private state
would otherwise become target-readable. ACS also anchors its home to a
canonical parent and opens each private lock and quarantine directory without
following symlinks before use. This keeps the target from redirecting private
state through a writable workspace, reading quarantine proof challenges, or
modifying operation-scoped executable snapshots through workspace permissions.

Logout deletes only the selected ACS Keychain item and succeeds when a valid
name is already absent. It refuses a quarantined name. The same binding
lifecycle is not yet connected to an interactive Codex run: there is no
`acs codex --auth`, Codex Profile overlay, plan/dry-run auth selection, or Codex
target adapter in this source.

Profiles persist neither credentials nor Keychain records. Deleting a Profile
therefore never deletes a named Codex authentication identity.

## Native evidence and its boundary

The promoted-artifact PR gate downloads the official `codex-cli 0.149.1`
Apple Silicon and Intel archives once, verifies their reviewed SHA-256 lock
entries before extraction, rejects unsafe archive contents, and installs only
the host's matching target. Each native job uses a temporary Keychain as its
sole search and default Keychain, restores the original configuration, and
deletes the temporary Keychain. The credential-free test covers the production
service namespace, metadata-only enumeration, duplicate service/account
collision, service/account isolation, exact record-size boundaries, and
failed-update byte preservation.

Before changing host Keychain configuration, the native gate creates a
deterministic private recovery root and writes a `0600` locator plus a `0600`
durable recovery artifact inside its disposable Keychain directory. The
artifact records the exact original search list (including an explicit empty
list), default Keychain, and recovery guidance. The versioned locator records
only a strictly validated relative state-directory component and a durable
`recovery-required` or `cleanup-only` phase; the artifact and disposable
Keychain use fixed leaf names. A stale,
linked, foreign-owned, incorrectly typed, incorrectly permissioned, or
symlink-traversed recovery path fails closed before host mutation.

Cleanup attempts both restorations even if one fails. The promoted macOS jobs
then run a separate `always()` recovery invocation, so a fresh process can find
the deterministic locator and repeat both restorations after a test-process
crash. After restoration, a helper process enters the validated state-directory
descriptor and invokes `security delete-keychain` with only the fixed relative
leaf name. This lets Security.framework remove daemon-managed Keychain state
without resolving a replaceable ancestor path. Recovery then proves that the
opened disposable Keychain inode has no remaining links before atomically
advancing to `cleanup-only`. A resumed cleanup-only recovery never repeats host
restoration and can finish after the artifact or state directory is already
gone. All reads, phase updates, and filesystem deletions remain relative to the
validated open descriptors; the locator is removed last, and an empty recovery
root is safely finalized. Entrypoint failures expose only stable recovery
categories, not locator paths, private paths, or artifact data.

Production writes explicitly request non-synchronizable,
when-unlocked-this-device-only items. All production queries prohibit
authentication UI. A file-backed temporary Keychain can omit the accessibility
attribute from the returned attribute dictionary. The live test therefore
requires the exact value when Security.framework returns it. Deterministic tests
separately prove the no-UI construction and fail-closed mapping for locked or
unavailable providers without exposing backend detail. Locking a disposable
default Keychain can itself trigger macOS access-control UI, so live
locked-Keychain and direct ACL inspection remain supplemental and are not
claimed as automated merge evidence. This is the strongest non-interactive
Security.framework evidence safely available from disposable CI state.

The same gate runs the installed target's exact version and contained
`login status` path with a synthetic durable record and home. It proves runtime
credential-store, login-method, and workspace precedence; no global-auth
interference; Seatbelt containment; projection disposal; quarantine cleanup;
and sentinel redaction without real credentials. Deterministic ACS tests cover
same-identity refresh and quarantine decisions. Interactive login completion
and target-origin token refresh require real account credentials and remain a
supplemental trusted-host smoke, not a PR merge criterion.

The repository-wide race suite remains mandatory but leaves opt-in native
Keychain and installed-target tests disabled. Race instrumentation can exceed
the production supervisor's fixed settlement deadline and correctly quarantine
the projection, so that instrumented outcome is not claimed as native target
evidence; the ordinary native test must settle completely.

## Official Codex behavior

Codex documents browser and device login, `codex login status`, `codex logout`,
automatic ChatGPT-token refresh, `$CODEX_HOME/auth.json`, and OS credential-store
modes in the [official authentication documentation](https://learn.chatgpt.com/docs/auth).
The [official managed-configuration documentation](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
defines `/etc/codex/requirements.toml` as the Unix system path for enforced
requirements.
ACS deliberately uses Codex file storage only inside temporary contained login
and status homes; its durable namespace is owned directly by ACS.

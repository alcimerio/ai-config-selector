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

Login requires interactive stdin and stdout. The current implementation accepts
ChatGPT authentication only and pins the exact output `codex-cli 0.149.1`.
API-key, non-interactive token injection, and credential import are unsupported.

## Contained login and cleanup

Before creating any temporary state, ACS verifies that its native Process
Sandbox is available for the workspace, Session root, Codex executable, and
runtime inputs. Codex also checks the optional managed-requirements file at
`/etc/codex/requirements.toml`. ACS grants an exact, read-only probe for that
file: Codex can enforce it when present and receives the normal not-found result
when absent, without gaining access to the rest of `/etc`. It then:

1. creates a leased private Session and synthetic home;
2. writes a private `.codex/config.toml` that selects file credential storage
   and forces the ChatGPT login method;
3. verifies the exact Codex CLI version inside the sandbox;
4. runs `codex login`, optionally with `--device-auth`, inside the same sandbox;
5. opens only the Session's `.codex/auth.json`, without following symlinks, and
   requires a private, regular, single-link file owned by the invoking user;
6. validates the bounded JSON schema and derives non-secret metadata before the
   first durable write;
7. atomically creates the named Keychain record and removes the temporary
   Session.

The temporary file necessarily contains credential bytes between successful
Codex login and Keychain storage. It is never a durable ACS provider and is not
copied to a Profile, log, plan, error, or command-line argument. Session cleanup
is logical removal; ACS does not claim physical erasure from the filesystem or
storage media. If contained-process cleanup is uncertain, login fails rather
than reporting a stored identity as safely completed.

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
3. verify native sandbox availability before Session creation;
4. create a leased Session plus synthetic `HOME` and durably mark both the
   identity and Session as recovery-owned before writing credential bytes;
5. write private `.codex/config.toml` and `.codex/auth.json` files with file
   credential storage, forced ChatGPT login, and the validated workspace
   restriction when present;
6. verify `codex-cli 0.149.1` and run `codex login status` inside the mandatory
   process sandbox;
7. prove contained-process cleanup, validate the final projected credential,
   make one typed commit-or-discard decision, remove the projection, and only
   then release the identity lock.

The generated configuration prevents Codex from falling back to an OS store or
another login method. The process receives the Session's synthetic `HOME`, so
the effective file location is that Session's `HOME/.codex/auth.json`; ACS does
not set the process to the invoking user's global Codex home.

Codex may refresh ChatGPT tokens during status. ACS atomically replaces the
Keychain payload only when the final file remains schema-valid and its login
method, workspace, and stable identity fingerprint equal the durable record.
The terminal dispositions are:

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

Before projecting credentials, ACS creates a private, secret-free marker under
`~/.acs/quarantine/codex-auth` and a private recovery-protection marker in the
Session lease directory. Quarantine metadata contains only its version, the
identity name, and the random Session identifier. It never contains credential
bytes, metadata fingerprints, tokens, workspace identifiers, or `auth.json`.

Recovery protection prevents normal abandoned-Session cleanup from reclaiming
a quarantined projection. The name remains blocked across ACS processes even
after the original file lock is released. `auth recover` acquires that name,
requires the protected Session lease to be inactive, revalidates the projection
against the current durable identity, and makes one idempotent decision:

- commit a different payload only when it is a valid same-identity refresh; or
- discard missing, unchanged, invalid, deleted, or identity-changing state.

Recovery removes the protected Session before deleting the identity marker. If
the Session is still active or logical removal cannot be proven, both markers
remain and the identity stays blocked. If a prior cleanup already removed the
Session, recovery clears the stale marker as an already-discarded projection.

Session removal is logical removal; ACS does not claim physical erasure from
the filesystem or storage media.

## Concurrency and current boundary

Login, status, recovery, and logout acquire a private, non-blocking file lock
for the selected name. Concurrent use of the same identity returns an in-use
error through final projection removal or quarantine; different names can
proceed independently. Keychain creation is also atomic, so a duplicate cannot
replace the existing record even across processes.

Logout deletes only the selected ACS Keychain item and succeeds when a valid
name is already absent. It refuses a quarantined name. The same binding
lifecycle is not yet connected to an interactive Codex run: there is no
`acs codex --auth`, Codex Profile overlay, plan/dry-run auth selection, or Codex
target adapter in this source.

Profiles persist neither credentials nor Keychain records. Deleting a Profile
therefore never deletes a named Codex authentication identity.

## Official Codex behavior

Codex documents browser and device login, `codex login status`, `codex logout`,
automatic ChatGPT-token refresh, `$CODEX_HOME/auth.json`, and OS credential-store
modes in the [official authentication documentation](https://learn.chatgpt.com/docs/auth).
The [official managed-configuration documentation](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
defines `/etc/codex/requirements.toml` as the Unix system path for enforced
requirements.
ACS deliberately uses Codex file storage only inside temporary contained login
and status homes; its durable namespace is owned directly by ACS.

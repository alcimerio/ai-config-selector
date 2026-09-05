# AI Config Selector

AI Config Selector (`acs`) creates named capability Profiles and launches a
process with only the selected configuration inside an ephemeral, native
sandbox.

The v0.4.0 contract is deliberately macOS-first:

- macOS 26 on `darwin/arm64` and `darwin/amd64`;
- Skills discovered from `~/.config/devin/skills` and `~/.agents/skills`;
- Devin launches with selected Skills and its allowlisted credential;
- a credential-free sandbox shell for inspecting the same isolation directly.

v0.3.3 is the final release with Linux support. The Bubblewrap implementation
remains in the source tree for possible future work, but v0.4.0 has no Linux
binary, installer path, native gate, or support commitment.

## Inspect saved Profiles

Use `acs profile list` to find stored Profiles and `acs profile show NAME` to
inspect persisted versions and selected Skills, including references to Skills
that no longer exist. These commands only read stored structure; source,
authentication, and runtime readiness remain unchecked. They create no directories
or Sessions and do not modify Profile or quarantine state.

Add `--json` for deterministic output format 1; `acs profile show --json NAME` is
also accepted. See the [inspection and JSON contract](docs/profile-inspection.md)
for status codes, exit behavior, limits, and examples. Run `acs profile --help`
for contextual help.

## Passive diagnostics (development source)

Run `acs doctor` for core host and trusted backend-file checks without an account
or optional clients. Add `--target devin`, `--target sandbox`, or
`--target codex-auth` to check only that workflow's executable availability.
`codex-auth` describes named authentication workflows, not interactive Codex
launch. Versions, authentication, and actual containment remain unchecked.

Run `acs profile validate NAME` to validate supported stored structure and resolve
selected Skill sources without constructing a launch plan. Unselected sources
are not required. Both commands accept `--json`, need no terminal, execute no
processes, and change no files. See the [passive diagnostics contract](docs/passive-diagnostics.md)
for the separate diagnostic JSON format, check IDs, exit behavior, and limits.

## Install

The latest published immutable release is v0.4.0. Download its release-specific
installer, inspect it, then run the local file:

```sh
release_version=v0.4.0
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
less install.sh
sh ./install.sh
"$HOME/.local/bin/acs" version
```

To build the current source on macOS instead:

```sh
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
./bin/acs version
```

A source build reports `acs devel`.

The installer accepts only macOS arm64 and amd64. It verifies the selected
archive against the release's `SHA256SUMS`, validates the embedded version and
archive structure, and refuses to replace an existing `acs` file. It defaults
to `~/.local/bin`, does not use `sudo`, and never edits shell startup files.

Release archives are unsigned and unnotarized. GitHub attestations and SHA-256
prove origin and byte identity; they do not represent Apple notarization or
malware review.

## macOS quickstart (development source)

Contextual help and the guidance below describe the current source build; the
published v0.4.0 installer does not include these new help and diagnostic commands. Use macOS
26 on Apple Silicon or Intel, Go 1.25 or later for the source build, and a real
terminal for Profile creation and interactive launch. The system
`/usr/bin/sandbox-exec` must be available; ACS checks it and fails closed.

Build using the source instructions above, then make that binary available in
this terminal (run this from the cloned repository):

```sh
export PATH="$PWD/bin:$PATH"
acs help
acs devin create-profile --help
acs doctor
acs doctor --target sandbox
```

For a Devin launch, install and authenticate Devin separately so `devin` is on
`PATH` and its credential is available at
`~/.local/share/devin/credentials.toml`. The sandbox-shell path below requires
neither Devin nor a Devin account; it uses the system `/bin/zsh -f`. Named
Codex login/status additionally require exactly `codex-cli 0.149.1` and an
available macOS Keychain, as described in the authentication section below.

ACS discovers selectable global Skills only in `~/.config/devin/skills` and
`~/.agents/skills`. Each immediate child directory must contain a regular
`SKILL.md`: for example, `~/.agents/skills/backend-review/SKILL.md`. A loose
`SKILL.md` at the root or deeper nested bundles are not catalog entries.
To add a small first Skill without overwriting an existing bundle:

```sh
mkdir -p "$HOME/.agents/skills"
mkdir "$HOME/.agents/skills/acs-first-review" && cat > "$HOME/.agents/skills/acs-first-review/SKILL.md" <<'EOF'
---
name: acs-first-review
description: Review code for correctness and useful tests.
---
Review the current changes for correctness and missing behavioral tests.
EOF
```

Create the Profile:

```sh
acs devin create-profile --name backend-review
```

Press Enter on Skills, select `acs-first-review` with Space/Enter, return with
Left/Esc, then choose Create Profile. `/` searches; Esc while searching clears
the filter. An empty catalog explains where to add Skills; an empty search
suggests clearing the filter. Restart creation after adding a bundle. Ctrl+C
cancels with exit 130 (confirm discarding a changed draft); no Profile is saved.
An empty Profile requires explicit confirmation, and existing names cannot be
overwritten.

Validate the saved Profile without runtime checks:

```sh
acs profile validate backend-review
```

From the workspace you want the sandboxed process to read and write, inspect
and launch the credential-free shell:

```sh
acs sandbox --profile backend-review --dry-run
acs sandbox --profile backend-review
```

Dry-run prints the planned selected contents and sandbox readiness without
allocating a Session. In the shell, inspect the synthetic home with
`find "$HOME" -maxdepth 5 -type f`, then type `exit` to return. To use Devin
with the same Profile after its separate installation and authentication:

```sh
acs doctor --target devin
acs devin --profile backend-review --dry-run
acs devin --profile backend-review
```

Devin dry-run also reports repository-local inheritance. Workspace-local
`.devin/skills` and `.agents/skills` remain under Devin's control; they are not
selectable global catalog roots and are not copied into the sandbox shell.
Next, read the isolation contract below and use `acs codex auth --help` for
named authentication or `acs sandbox --help` for shell syntax.

## Command help and grammar (development source)

`acs help` and `acs --help` print root help. Every command path supports both
forms, for example `acs help codex auth login` and
`acs codex auth login --help`. Help succeeds on stdout with exit 0, requires no
interactive terminal, and performs no discovery, credential access, Profile
writes, Session allocation, target launch, or recovery sweep. Invalid syntax
fails on stderr with exit 1 and points to contextual help; an empty invocation
also fails with root guidance.

Write the complete command path first, then its flags in any order:

```sh
acs devin --dry-run --profile backend-review
acs codex auth login --device-auth --name work
```

Values follow their flag as one separate, nonempty token; flags occur at most
once. Help may appear among otherwise valid flags and does not require the
command's mandatory name flag. Invalid flags or malformed values still fail
even when `--help` is present. Positional arguments after a command, `--flag=value`,
`--` separators, target pass-through, backend selection, and sandbox bypass
are rejected. Existing target exit codes and Profile cancellation semantics
are preserved.

## Profiles

Create a Profile with the interactive builder:

```sh
acs devin create-profile --name backend-review
```

Profiles are stored under `~/.acs/profiles`. Names contain 1–64 letters,
numbers, dots, underscores, or hyphens and must begin with a letter or number.
ACS refuses to overwrite an existing Profile.

Inspect the selected Skills, Devin-specific repository-local inheritance, and
native sandbox readiness without creating a Session:

```sh
acs devin --profile backend-review --dry-run
```

Launch Devin:

```sh
acs devin --profile backend-review
```

The Devin path creates a synthetic home, materializes selected Skills, copies
only `~/.local/share/devin/credentials.toml` when present, verifies the Skill
catalog and authentication inside Seatbelt, and then starts Devin with its
workspace-trust prompt disabled. The trust decision is redundant inside ACS's
required fail-closed sandbox and could not persist in the ephemeral synthetic
home. This does not change Devin's permission mode. There is no unsandboxed
fallback.

## Codex authentication identities (development source)

The current development source can create ACS-owned, named ChatGPT login
identities and verify them through an isolated Codex Session:

```sh
acs codex auth login --name work
acs codex auth login --name personal --device-auth
acs codex auth list
acs codex auth status --name work
acs codex auth recover --name work
acs codex auth logout --name work
```

Names use 1–64 lowercase ASCII letters, numbers, dots, underscores, or hyphens
and must begin with a letter or number. Login requires interactive stdin and
stdout and the supported `codex-cli 0.149.1`. ACS runs that login inside its
mandatory process sandbox with a private synthetic home and file credential
storage, validates the resulting credential, then stores one versioned record
per name in the macOS Keychain under an ACS-specific service. Existing names
are never replaced implicitly. `list` retrieves only non-secret Keychain
attributes; `logout` is idempotent for an absent valid name.

`status` acquires exactly one named identity before creating a Session, copies
it into that Session's private synthetic home, forces Codex file credential
storage plus the validated login-method/workspace restrictions, and runs the
version-pinned `codex login status` inside the mandatory process sandbox. An
unchanged projection is discarded. A schema-valid token refresh replaces the
Keychain record only when its method, workspace, and identity fingerprint still
match. Projected deletion, logout, schema changes, or identity changes never
delete or replace the last valid durable identity.

If contained-process settlement, durable replacement, or logical projection
removal is uncertain, the Session and identity become quarantined and new use
of that name fails closed. `recover` proves the protected Session is inactive,
makes one commit-or-discard decision, removes the projection, and then clears
the secret-free quarantine marker. Recovery is idempotent when no marker
remains.

These identities are separate from the invoking user's global Codex login.
ACS never reads, imports, replaces, deletes, or falls back to global
`~/.codex/auth.json` or Codex's global OS-store namespace. Running `codex login`
outside ACS may change that global login, but it does not change ACS-owned
records. A locked, unavailable, ambiguous, or corrupt Keychain fails closed;
there is no plaintext fallback.

This development slice manages durable identities and binds one identity to a
contained status probe. It does not yet bind an identity to a Codex launch,
expose `--auth`, persist a Codex Profile overlay, or provide the Codex target
adapter. Deleting a Profile never deletes an identity.

See [named Codex authentication and contained status](docs/codex-auth.md) for the
storage, isolation, failure, and cleanup contracts.

## Inspect the sandbox directly

Open the fixed system shell inside the selected Profile's isolated Session:

```sh
acs sandbox --profile backend-review
```

This always launches `/bin/zsh -f`. It does not consult `$SHELL`, load user
startup files, invoke Devin, copy a Devin credential, or run Devin preflights.
The selected Skills are available under the synthetic Session home, so commands
such as these show the process's real view:

```sh
pwd
echo "$HOME"
find "$HOME" -maxdepth 5 -type f
env | sort
```

Use dry-run to inspect planned Session contents and Seatbelt readiness without
creating a Session or starting a shell:

```sh
acs sandbox --profile backend-review --dry-run
```

## Isolation contract

On supported macOS hosts, ACS verifies the root-owned, non-writable system
`/usr/bin/sandbox-exec` and applies a generated default-deny Seatbelt policy to
the target and its descendants.

The contained process can:

- read and write the selected workspace;
- read and write its leased Session, including synthetic home and temporary
  storage;
- read the minimal macOS runtime and fixed-PATH commands required to run;
- use the invoking terminal, signals, resize events, and normal outbound IP and
  DNS.

It cannot read unrelated host files through tested direct or symlink paths,
write outside the workspace or Session, inherit arbitrary host environment
variables or file descriptors, or use unrelated host Unix sockets. ACS uses a
clean environment with synthetic `HOME`, XDG paths, temporary paths, and a
fixed `PATH`.

ACS waits for the contained process tree to settle before deleting the Session.
If cleanup cannot prove that descendants are gone, the Session remains leased
and quarantined instead of being treated as safely removed.

There is no unsandboxed fallback. ACS will not start the requested process
without the required sandbox. ACS is not an egress firewall: outbound network
destinations are neither filtered nor approved.

## Failure categories

Sandbox failures use stable categories without exposing generated policy,
credentials, private paths, environment values, backend output, or terminal
control characters:

- `unsupported_platform`
- `backend_unavailable`
- `policy_rejected`
- `sandbox_verification_failed`
- `unsafe_path`
- `invalid_environment`
- `invalid_descriptor`
- `setup_failed`
- `process_start_failed`
- `process_wait_failed`

Devin preflights additionally report sanitized Skill-isolation and
authentication failures. Ordinary target exits preserve the target exit code.

## Release evidence

A release candidate is built once, installed, and exercised as the exact same
bytes on macOS 26 `darwin/arm64` and `darwin/amd64`. Both native jobs run normal,
race, installed-artifact, containment, terminal, descendant, and cleanup tests.
Attestation and immutable publication depend on both jobs. Linux compilation is
recorded separately as a non-blocking portability observation and is not release
evidence.

The credential-free candidate gate is authoritative. The optional authenticated
Devin smoke is supplemental and never replaces the two native gates.
Development named-authentication changes additionally gate the locked official
`codex-cli 0.149.1` target on both native runners with disposable Keychain,
synthetic-home, and mandatory Seatbelt evidence. Real login and target-origin
refresh observation remains supplemental and is never a CI credential gate.

## Compatibility and limitations

- Devin is the only production CLI adapter.
- Skills is the only production Profile category.
- Profiles cannot yet be listed, edited, deleted, imported, or exported through
  the CLI.
- Repository-local Skills remain under Devin's control and are not copied into
  the credential-free sandbox shell.
- macOS 26 arm64 and amd64 are the only v0.4.0 supported platforms.
- Linux source is retained without binaries, native CI, or support guarantees.
- Source builds and authenticated smoke runs are development evidence, not
  immutable-release evidence.
- ACS does not manage MCP servers, hooks, instructions, agents, or arbitrary
  target settings.
- The development Codex authentication commands can project a named identity
  for contained status verification, but do not yet launch an interactive Codex
  process or expose run-time auth selection.
- ACS has no automatic updater, package-manager distribution, or uninstaller.

Read [the architecture](docs/architecture.md), [contribution guide](CONTRIBUTING.md),
and [v0.4.0 release notes](docs/releases/v0.4.0.md) for more detail.

## License

ACS is available under the [MIT License](LICENSE).

### Profile repository transactions

Development-source Profile creation uses a revisioned byte repository with checked
synchronization and explicit process-interruption recovery. Existing inspection
and diagnostics remain passive. If creation reports an uncertain or committed
transaction error, rerun the same create-profile command interactively to reach
recovery before its duplicate-name check. See the [repository transaction
contract](docs/profile-repository-transactions.md) for outcomes, byte revisions,
filesystem limits and native evidence; no edit/rename/delete commands are added.

# Manual binary upgrades, rollback and data recovery

[Documentation index](../README.md)

For supported direct user-owned Apple Silicon installs, `acs update --check`
checks availability and `acs update [vMAJOR.MINOR.PATCH]` replaces only the
executable. Neither updates nor manual binary selection back up, migrate or
recover stored data. Keep the known-good binary and private Profile backups.

This procedure applies to macOS 26 on Apple Silicon (`darwin/arm64`), including
older installs without an updater. Choose a compatible release from
[GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases).
For unpublished builds, use the
[contributor candidate procedure](../development/releasing.md#test-a-development-candidate).
An older binary cannot acquire newer recovery capabilities by being selected.

## Discover the executable you actually use

```sh
type -a acs
command -v acs
```

Inspect aliases, functions, wrappers and symlinks until you identify the trusted
regular executable's absolute path. Use `ls -ld` and `readlink` to follow links;
never execute shell text printed by discovery. Run that explicit path with
`version` and record its SHA-256 and release/source identity. A development
version string alone does not identify bytes.

Finish Profile editors and contained work normally before switching. Preserve
the owning binary and recover uncertain transactions or authentication operations
first. An exited terminal or old timestamp does not prove descendants settled.
Already-running processes keep their bytes, but a delayed supervisor or MCP
helper may open the replaced path; restart affected Sessions normally when
helper compatibility is uncertain.

Use one dedicated Bash so options and trial PATH changes remain local:

```sh
/bin/bash --noprofile --norc
```

Choose trusted directories owned by your user. If `cd "$HOME"; pwd -P` reveals a symlink,
use the physical absolute path for `maintenance_root`. The installer rejects
symlink ancestors, relative paths, `.`/`..`, trailing slashes, colons, single
quotes and non-printable/non-ASCII characters. Spaces are supported. Use a new
maintenance directory for each attempt; never mix existing evidence.

## Retain the old binary and inspect the installer

Set `old_bin` to the inspected path. Set `release_version` to the chosen tag
and `installer_sha256` to its installer asset digest from
[GitHub release metadata](https://api.github.com/repos/alcimerio/ai-config-selector/releases/latest).
Use the hexadecimal digest without its `sha256:` prefix. For another release,
select the matching tag through
`https://api.github.com/repos/alcimerio/ai-config-selector/releases/tags/TAG`.
Set `binary_sha256` to the digest of the `acs` member from that release
archive, after verifying the archive against its reviewed asset digest or
`SHA256SUMS`. The installer, archive and binary digests identify different files;
keep all inputs tied to the same release. Read its compatibility notes first.

Run the preparation, staging and switching blocks in order in the same
maintenance shell. `set -e` stops that shell on a
failed check and returns to its parent's PATH; no startup file changes
automatically.

<!-- example: prepare -->
```sh
set -eu
umask 077
old_bin="/absolute/path/to/known-good/acs"
release_version='vMAJOR.MINOR.PATCH'
installer_sha256='REVIEWED_INSTALLER_SHA256'
binary_sha256='REVIEWED_BINARY_SHA256'
maintenance_root="$HOME/ACS Maintenance $release_version"
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
path_before_upgrade="$PATH"
stage_bin="$maintenance_root/selected/bin"
rollback_bin="$maintenance_root/known-good/bin"

case "$old_bin" in /*) ;; *) exit 1 ;; esac
test -f "$old_bin"
test ! -L "$old_bin"
test -x "$old_bin"
mkdir "$maintenance_root"
mkdir "$maintenance_root/downloads" "$maintenance_root/known-good"
mkdir "$rollback_bin"
cp -p "$old_bin" "$rollback_bin/acs"
cmp "$old_bin" "$rollback_bin/acs"
"$rollback_bin/acs" version > "$maintenance_root/known-good/version.txt"
cat "$maintenance_root/known-good/version.txt"
(
  cd "$rollback_bin"
  shasum -a 256 acs > "$maintenance_root/known-good/SHA256SUMS"
)

cd "$maintenance_root/downloads"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
printf '%s  install.sh\n' \
  "$installer_sha256" \
  > installer.sha256
shasum -a 256 -c installer.sha256
less install.sh
```

Inspect the whole installer before continuing. Its only option is `--bin-dir`;
it pins its own release, checks archive structure/checksum and requires exactly
`acs $release_version`. It refuses any existing `acs`, including a dangling
symlink. Do not remove the working binary to get past this check.

## Stage and verify before switching

<!-- example: stage -->
```sh
sh ./install.sh --bin-dir "$stage_bin"
"$stage_bin/acs" version > "$maintenance_root/selected-version.txt"
printf 'acs %s\n' "$release_version" > "$maintenance_root/expected-version.txt"
cmp "$maintenance_root/expected-version.txt" "$maintenance_root/selected-version.txt"

printf '%s  acs\n' "$binary_sha256" > "$maintenance_root/selected-binary.sha256"
(
  cd "$stage_bin"
  shasum -a 256 -c "$maintenance_root/selected-binary.sha256"
)
cat "$maintenance_root/selected-version.txt"
```

Expect the selected release version and a matching checksum. Keep the installer
and verification records privately. `version` and staging do not create Sessions or migrate data.
The release is unsigned and unnotarized: checksums establish byte identity,
attestations establish provenance for their subjects, and neither establishes
Apple approval or a malware review. Stop on native trust or sandbox failure. Do
not strip quarantine, disable Gatekeeper, ad-hoc sign or weaken Seatbelt.

## Deliberately switch, and roll back the executable

This selects the new binary only in the maintenance shell:

<!-- example: switch -->
```sh
export PATH="$stage_bin:$path_before_upgrade"
hash -r
type -a acs
test "$(command -v acs)" = "$stage_bin/acs"
acs version > "$maintenance_root/resolved-version.txt"
cmp "$maintenance_root/expected-version.txt" "$maintenance_root/resolved-version.txt"
```

The equality check rejects aliases/functions and unexpected paths; stop if it
fails. Bash uses `hash -r`; zsh uses `rehash`. Existing terminals and processes do
not switch. To persist a verified choice, deliberately edit your own PATH setup,
retain the old setting, and recheck from a fresh terminal. Review wrappers and
IDE launch settings separately.

For rollback in the same shell, verify and select the retained executable:

<!-- example: rollback -->
```sh
(
  cd "$rollback_bin"
  shasum -a 256 -c "$maintenance_root/known-good/SHA256SUMS"
)
export PATH="$rollback_bin:$path_before_upgrade"
hash -r
type -a acs
test "$(command -v acs)" = "$rollback_bin/acs"
acs version > "$maintenance_root/rollback-version.txt"
cmp "$maintenance_root/known-good/version.txt" "$maintenance_root/rollback-version.txt"
```

After a shell restart, use its explicit absolute path until PATH is restored and
checked. Keep the staged binary too: it may own newer state that needs recovery.

## Binary rollback is not a data downgrade

Verify compatibility with all stored formats before letting a different binary
read, write or launch against your ACS home. Do not give newer Profiles to an
older writer, or newer protected Session state to an older launcher. If unsure,
stop after `version` and use the compatible owner for inspection and recovery.
Never overwrite newer live state with an old backup as routine rollback.

Passive Profile inspection does not rewrite legacy v1/v2. Confirmed mutations
preview any canonical v1-to-v2 conversion; `acs profile migrate NAME` explicitly
adopts v3 and common material paths. Migration preserves legacy workspace write
authority; making it read-only is a separate choice. Profiles, history,
transactions, Sessions and Keychain records have independent format/lifecycle
rules. Installing a binary changes none of them. See [Profiles](profiles.md).

Before a schema-changing write, settle transactions with their compatible owner,
close all editors/writers and prevent other writers during this copy. It covers
only direct JSON files in a trusted, quiescent Profile directory; it is not an
atomic snapshot, portable export or transaction-recovery image. Stop on an
unexpected path or copy failure and preserve the original.

<!-- example: profile-backup -->
```sh
profile_dir="$HOME/.acs/profiles"
backup_dir="$maintenance_root/profiles-before-changes"
test ! -L "$HOME/.acs"
test -d "$profile_dir"
test ! -L "$profile_dir"
mkdir "$backup_dir"
for profile_file in "$profile_dir"/*.json; do
  if [ ! -e "$profile_file" ] && [ ! -L "$profile_file" ]; then
    continue
  fi
  test -f "$profile_file"
  test ! -L "$profile_file"
  cp -p "$profile_file" "$backup_dir/"
  chmod 0600 "$backup_dir/${profile_file##*/}"
  cmp "$profile_file" "$backup_dir/${profile_file##*/}"
done
```

Keep this backup outside repositories, shared folders and uploads. Record which
binary wrote it and subsequent changes. It excludes Skill source contents,
Sessions, transaction evidence and Keychain credentials. ACS has no automatic
backup-restore or schema-downgrade command. Preserve current data separately
before planning a case-specific restore against a settled compatible repository;
never replace live locks or journals with this copy.

### Explicit Profile migration

Use the inspected compatible binary's absolute path, even if you just rolled
command selection back. Preview migration only for a legacy Profile you intend
to adopt. Cancellation makes no decision; after confirmation, heed `not
committed`, `committed`, `unknown` and `recovery required` literally. A strict
maintenance shell exits on cancellation or failure; use the recovery shell below
for inspection, and never blindly retry an unknown outcome.

<!-- example: migrate -->
```sh
source_bin="/absolute/path/to/compatible-source/acs"
"$source_bin" profile migrate backend-review
```

After a confirmed migration, inspect the result. For an optional exchange file,
first `cd "$maintenance_root"` so it stays private. Export refuses overwrite and
omits source contents, resolved paths, history, Sessions and authentication; it
is not a backup. Import validation checks structure, not target/auth readiness.

<!-- example: after-migrate -->
```sh
"$source_bin" profile show backend-review
"$source_bin" profile validate backend-review
"$source_bin" profile export backend-review --file backend-review.acs-profile.json
"$source_bin" profile import validate --file backend-review.acs-profile.json
```

## Recover a Profile transaction with a compatible binary

Start a separate recovery shell, including from the strict maintenance shell:

<!-- example: recovery-shell -->
```sh
/bin/bash --noprofile --norc
```

Initialize `source_bin` in this new shell to the inspected compatible owner.
Disabling inherited exit-on-error keeps inspection possible after a missing
Profile or failed or cancelled recovery. Read each command's
output and exit status. A nonzero result is not automatically success. Use the
explicit
[return step](#leave-the-recovery-shell) when finished.

<!-- example: recovery-inspection -->
```sh
# Keep the recovery shell open for inspection after nonzero ACS statuses.
set +e
source_bin="/absolute/path/to/compatible-source/acs"
"$source_bin" version
"$source_bin" profile list
"$source_bin" profile show backend-review
```

`profile validate NAME` also checks selected Skills; `doctor` checks passive
prerequisites. None of these acquires a write lock, recovers a transaction,
cleans artifacts or proves runtime/auth readiness. Inspection is not a snapshot;
a pending rename can expose both names.

- Pre-commit conflict/cancellation without recovery required: inspect, reload and
  preview before another write.
- Committed with only reporting failed and no recovery required: inspect the
  committed result; do not replay or recover unnecessarily.
- Unknown or recovery required: publication or cleanup may remain. Recover before
  considering a new mutation.

For the last case, use a compatible executable that supports explicit Profile
recovery:

<!-- example: profile-recovery -->
```sh
"$source_bin" profile recover
```

Follow [Profile transaction recovery](profiles.md#uncertain-outcomes-and-recovery)
for exact outcomes and observation limits. Inspect again, including both names
after a rename:

<!-- example: recovery-follow-up -->
```sh
"$source_bin" profile list
"$source_bin" profile show backend-review
```

A missing name can still exit 1 without closing this shell. Do not create an
unrelated Profile or blindly retry the original mutation. Recovery aborts
recognized preparation before a decision; afterward it rolls forward or fails
while preserving evidence. It is not undo, and success with no pending journal
does not prove what an earlier lost response meant.

Keep blocked journal/path/schema/link/sync evidence and the sanitized error.
The `.profile-transaction-lock` in `~/.acs/profiles` is permanent; an in-use
operation, including a stopped live process, still owns it. Wait for its owner,
then retry supported recovery. Never delete, replace, rename or reclaim locks or
`.profile-transaction-*` artifacts. Copying a journal does not preserve inode/link
proof or authorize replay elsewhere. See the
[transaction contract](../development/architecture.md#profile-repository-transactions) for filesystem limits;
interruption tests do not prove arbitrary-volume power-loss safety.

## Recover a named Codex identity without exposing credentials

Named identities live separately in macOS Keychain; a copy of `~/.acs` does not
export them. Restore normal Keychain access when locked/unavailable, and keep
rejected schema or integrity evidence. Use the compatible binary and
[recovery shell](#recover-a-profile-transaction-with-a-compatible-binary):

```sh
"$source_bin" codex auth list
```

Listing reads non-secret metadata without clearing quarantine. After the owner
and descendants settle, request proof-gated recovery:

```sh
"$source_bin" codex auth recover --name work
```

Recovery needs no new login. An unlocked lease alone is insufficient; missing
proof, active ownership or changed/invalid generations keep the identity blocked.
Preserve the compatible binary, locks, projection, Session, proof and quarantine
when recovery refuses. Logout cannot bypass quarantine. See
[Codex recovery](codex.md#quarantine-and-recovery) for refresh eligibility and
marker ordering; `auth status` is an active probe that can refresh credentials.

For tracked Sessions, use `acs session list`, `acs session inspect ID` and then
`acs session recover ID` after owners settle. It neither kills a process nor
accepts a raw path; see [Session operations](session-operations.md).

Never delete protected state by hand, copy global Codex credentials into ACS or
publish secrets, projections, Session contents or proof files. Profile deletion
and restoration do not delete or restore identities.

## Leave the recovery shell

After preserving unresolved evidence, return with an explicit successful shell
status so a failed final inspection does not close the strict parent. This does
not mark the inspection or recovery successful:

<!-- example: recovery-exit -->
```sh
exit 0
```

## Validation boundary

The automated examples test shell behavior with fake downloads/executables,
private temporary homes, paths with spaces, verification failures, shadowing,
selection/rollback, protected-state preservation and recovery-shell returns.
They do not establish a real-user upgrade, real-account login, hosted inference
or sustained daily use. Native gates and optional authenticated observations
have separate scopes in [testing](../development/testing.md).

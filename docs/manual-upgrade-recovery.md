# Manual binary upgrades, rollback and data recovery

ACS has no updater. Install a selected immutable release into a new directory,
verify it, and deliberately change which executable your shell selects. Keep the
known-good binary and private local Profile backups. Changing the executable does
not migrate stored Profiles, recover a transaction, or move authentication records.

This guide targets macOS 26 on Apple Silicon and Intel. As verified on
2026-09-06 UTC, the [latest published release is immutable v0.4.0](https://github.com/alcimerio/ai-config-selector/releases/tag/v0.4.0).
The [release metadata](https://api.github.com/repos/alcimerio/ai-config-selector/releases/tags/v0.4.0)
identifies its four downloadable assets. The examples deliberately pin that
release; they do not track a moving `latest` download URL. Selecting v0.4.0 when
you already use newer development source is a binary downgrade.

## Check which capabilities belong to your binary

| Capability | Published v0.4.0 | Current development source |
| --- | --- | --- |
| `version`, Devin Profile creation/launch, sandbox shell, launch dry-run | Available | Available |
| Contextual help, `profile list/show/validate`, `doctor` | Unavailable | Available; passive inspection |
| `profile edit/clone/rename/delete` | Unavailable | Available with confirmed, conditional writes |
| Transaction recovery before interactive `devin create-profile` | Unavailable | Available before the duplicate-name check |
| Named `codex auth` commands, including `recover` | Unavailable | Available with the Keychain and Session protections below |

The release command boundary is defined by the
[v0.4.0 command dispatcher](https://github.com/alcimerio/ai-config-selector/blob/d5f333c0cf4e32334a92c5fca77a8af0bcb4cd64/internal/cli/cli.go).
Its creation command does **not** implement the newer transaction recovery entry
point. Staging this release cannot add recovery capabilities from current main.
For source-only steps below, retain the compatible source binary that owns the
state, or build a reviewed compatible revision using the [source instructions](../README.md#install).
Record its revision and binary SHA-256: `acs devel` alone does not identify a build.
Development candidate artifacts may report `v0.4.0` too; the version string alone
does not identify the published release bytes.

## Discover the executable you actually use

In your usual terminal, inspect command resolution before making changes:

```sh
type -a acs
command -v acs
```

Read the output. An alias, function, wrapper, cached command, or another directory
earlier in `PATH` can select a different binary from `~/.local/bin/acs`. Inspect
any wrapper and follow each symlink with `ls -ld` and `readlink` until you have the
trusted regular executable's absolute path. Do not execute shell text printed by
discovery commands. Run that explicit path with `version` and retain its identity.

Finish existing Profile editors and contained workloads through their normal
interfaces before changing the binary used for new work. If a transaction or
authentication operation is uncertain, preserve its owning binary and follow the
recovery sections first. An exited terminal or an old timestamp is not proof that
contained descendants have settled.

The maintenance examples below use one dedicated Bash shell, so shell options and
the trial `PATH` change last only for that shell:

```sh
/bin/bash --noprofile --norc
```

Use trusted, user-owned directories. Check `cd "$HOME"` followed by `pwd -P`:
if your home path contains a symlink, use its physical absolute path for
`maintenance_root` below. The installer rejects symlink ancestors, relative paths,
`.`/`..` components, trailing slashes, colons, single quotes and non-printable or
non-ASCII characters in its destination. Spaces are supported. Choose a new
maintenance directory for each attempt; an existing directory makes this example
stop instead of mixing old and new evidence.

## Retain the old binary and inspect the selected installer

Edit `old_bin` to the resolved executable you inspected. The binary staging,
switch, rollback and optional backup blocks run in order in the same maintenance
shell; stop on any unexpected result. `set -e` ends that shell on a failed check,
returning to the parent shell's original PATH.
No shell startup file changes automatically.

<!-- example: prepare -->
```sh
set -eu
umask 077
old_bin="/absolute/path/to/known-good/acs"
maintenance_root="$HOME/ACS Maintenance v0.4.0"
release_version=v0.4.0
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
  '6cd299134406d2551ea26adec240aee704debbba3e76d73eac93ead7729db3b4' \
  > installer.sha256
shasum -a 256 -c installer.sha256
less install.sh
```

Inspect the entire downloaded installer before running the next block. Its only
option is `--bin-dir`; it has no update, overwrite or version-selection option.
The embedded release selects the archive and `SHA256SUMS`, checks checksum and
archive structure, and requires exactly `acs v0.4.0` from the extracted executable.
It refuses any existing destination named `acs`, including a dangling symlink.
Do not remove your working binary to make this check pass.

These are the verified v0.4.0 archive identities; the installer downloads the one
matching `uname -m` from the pinned release URL:

| Asset | SHA-256 in the release's `SHA256SUMS` |
| --- | --- |
| [`acs_0.4.0_darwin_arm64.tar.gz`](https://github.com/alcimerio/ai-config-selector/releases/download/v0.4.0/acs_0.4.0_darwin_arm64.tar.gz) | `fab58eff46bb29d1aaed797530a63e617be5ed5771a4ebafc584cddcf510ee5a` |
| [`acs_0.4.0_darwin_amd64.tar.gz`](https://github.com/alcimerio/ai-config-selector/releases/download/v0.4.0/acs_0.4.0_darwin_amd64.tar.gz) | `a69264fa7baf9dcf19bfcb5bb34495f1f0eeaed08071993896f4ff38688b59fc` |

The installer digest above comes from the release asset metadata. The binary
digests below were computed from the regular `acs` entries in those verified
archives; they are distinct from the archive digests. For any other release,
inspect that release's metadata, installer, compatibility notes and artifacts,
then update all version and digest values together. Do not guess future URLs or
reuse these digests with another version.

## Stage and verify before switching

<!-- example: stage -->
```sh
sh ./install.sh --bin-dir "$stage_bin"
"$stage_bin/acs" version > "$maintenance_root/selected-version.txt"
printf 'acs %s\n' "$release_version" > "$maintenance_root/expected-version.txt"
cmp "$maintenance_root/expected-version.txt" "$maintenance_root/selected-version.txt"

case "$(uname -m)" in
  arm64 | aarch64)
    binary_sha256=c66e10892617324a976e7f113f2af6e6f6e78949727117d567704cec4eae1284
    ;;
  x86_64 | amd64)
    binary_sha256=0e97ddf83c22979a2dec336026fe29615867a9d637c665be7ad38cb763251101
    ;;
  *) exit 1 ;;
esac
printf '%s  acs\n' "$binary_sha256" > "$maintenance_root/selected-binary.sha256"
(
  cd "$stage_bin"
  shasum -a 256 -c "$maintenance_root/selected-binary.sha256"
)
cat "$maintenance_root/selected-version.txt"
```

Expect `acs v0.4.0` and a successful checksum check. Retain the inspected installer,
its checksum and the binary/version records in the private maintenance directory.
The version command does not create a Session or mutate Profile/authentication
state. Staging only places a binary; it does not inspect or migrate your data.

Archives are unsigned and unnotarized. Checksums establish byte identity against
their trusted reference; release attestations provide separate origin evidence.
Neither grants Apple notarization or proves malware safety. If native trust or
sandbox checks refuse execution, stop and retain the failure evidence. Do not
strip quarantine attributes, disable Gatekeeper, ad-hoc sign the binary, or weaken
the sandbox to make the example succeed.

## Deliberately switch, and roll back the executable

This switch retains both the original path and a checked copy of the old binary.
It changes command resolution in the maintenance shell; it does not overwrite
`~/.local/bin/acs` or reinterpret the installer as an updater.

<!-- example: switch -->
```sh
export PATH="$stage_bin:$path_before_upgrade"
hash -r
type -a acs
test "$(command -v acs)" = "$stage_bin/acs"
acs version > "$maintenance_root/resolved-version.txt"
cmp "$maintenance_root/expected-version.txt" "$maintenance_root/resolved-version.txt"
```

The `command -v` equality check rejects alias/function shadowing and an unexpected
selected path. Do not proceed if it fails. In Bash, `hash -r` clears cached command
paths; in your usual zsh terminal use `rehash`, then repeat discovery and explicit
version checks. Existing terminals and already-running processes do not switch
just because another terminal's PATH changed. To persist a verified choice, edit
your own shell's PATH configuration deliberately, retain the previous setting,
open a fresh terminal and check resolution again. Wrappers, aliases and IDE launch
settings need their own explicit review.

To select the retained old binary in the same maintenance shell:

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

After a shell restart, use the retained binary's explicit absolute path until you
have deliberately restored PATH and checked it. Exiting the maintenance shell also
returns to the parent shell's original resolution. Keep the staged binary as well:
you may need it to read or recover state created by that version.

## Binary rollback is not a data downgrade

Before letting a different version read, write or launch against your ACS home,
verify its compatibility with **all** stored formats and lifecycle protections.
Do not feed newer-format Profiles to an older writer, even if it can partially
decode them. Do not run an older launcher against newer active/protected Session
state. If compatibility is unknown, stop after `version` and use the owning
compatible binary for inspection and recovery. An old backup must not overwrite
new-format live data as a routine fix.

Current source writes Profile envelope v3 with independently versioned common
Skills/workspace payloads and explicit target overlays. New Profiles default to
read-only workspace authority; legacy v1/v2 remains writable until explicit
migration or a later supported edit changes that intent.
Passive list/show/validate and load do not rewrite legacy files. Confirmed edit,
clone and rename show the exact canonical result and explicitly preview any v1
`skillReferences` to v2 `categories.skills` conversion; clone leaves its source
unchanged. A v2 rewrite can also change ordering, defaults and formatting. The
separate `acs profile migrate NAME` command adopts v3 and common material paths.
transaction journal's format version is separate: recovery settles recorded bytes
without decoding or migrating them. Installing or switching the binary changes
none of these representations. See the [mutation guide](profile-mutations.md).

Before a confirmed schema-changing write, keep a private local backup of the
original Profile bytes. First settle pending transactions using their compatible
owner, close all editors/writers and prevent other writers during the copy. This
example copies only direct Profile JSON files into a new directory; it is not an
atomic snapshot, portable export, or transaction-recovery image. Use it only with
an ordinary, trusted, quiescent Profile directory. Unexpected paths or copy errors
mean the backup is incomplete; preserve the original and stop.

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

Keep backups outside repositories, shared folders and uploads. Record privately
which binary/revision wrote each format and which changes have occurred since
the backup. The copy does not include Skill source contents, Session state,
transaction evidence, or Keychain credentials. ACS has no supported CLI import,
backup restore or schema-downgrade command. If later recovery requires a restore,
preserve the current data separately and plan it against the exact compatible
schema and settled repository; do not replace the live tree, locks or journals
with this copy. Missing, corrupt or unsupported data may require case-specific
maintainer help instead of an automatic repair.

## Recover a Profile transaction with compatible development source

The inspection and recovery procedures below use a separate interactive shell.
Start it with this command, including when you are still in the maintenance Bash:

<!-- example: recovery-shell -->
```sh
/bin/bash --noprofile --norc
```

The setup below disables exit-on-error inside this new recovery shell, including
when its parent exports shell options. A missing Profile, recovered duplicate name
or cancelled builder must leave you able to inspect the result. The earlier
maintenance shell retains its fail-fast settings; installer, hash, version and
selection failures must still stop that workflow.
Read each recovery command's output and status before choosing the next step;
a nonzero status is not automatically success. When finished inspecting and
interpreting the results, use the [explicit return step below](#leave-the-recovery-shell)
to return to the parent without propagating a failed final inspection into its
fail-fast setting.

Initialize `source_bin` **in this recovery shell** to the inspected, compatible
source executable, not the staged v0.4.0 binary. Keep this shell for the Profile
and named-authentication recovery steps. These commands inspect stored structure
without changing it:

<!-- example: recovery-inspection -->
```sh
# Keep the recovery shell open for inspection after nonzero ACS statuses.
set +e
source_bin="/absolute/path/to/compatible-source/acs"
"$source_bin" version
"$source_bin" profile list
"$source_bin" profile show backend-review
```

`profile validate NAME` additionally checks selected Skill sources; `doctor`
checks passive prerequisites. None of these commands recovers a transaction,
acquires its write lock, cleans artifacts, or establishes runtime/auth readiness.
Inspection is not a snapshot: a pending rename can expose both names.

Follow the actual outcome, not just the exit code:

| Reported outcome | Safe next step |
| --- | --- |
| Ordinary pre-commit conflict/cancellation, no recovery required | Stored data was not replaced by that request; inspect, explicitly reload and preview again before another write. |
| Committed, only reporting failed, no recovery required | Inspect the committed result; there is no reason to replay the mutation or invoke repository recovery. |
| Unknown, or recovery required with any commitment state | Publication may already exist or cleanup may remain; use explicit recovery before considering a new mutation. |

For the last row, use the valid Profile name printed in the error, in a real
interactive terminal, for example:

<!-- example: profile-recovery -->
```sh
"$source_bin" devin create-profile --name backend-review
```

This entry point recovers the previous repository transaction **before** checking
whether that name exists. An already-published name then produces a duplicate
error. If the builder opens, cancel it without saving; exit 130 from that
cancellation does not undo recovery that already finished. Then run list/show
again in the recovery shell, including both names from a rename, for example:

<!-- example: recovery-follow-up -->
```sh
"$source_bin" profile list
"$source_bin" profile show backend-review
```

A still-absent name can again return exit 1 without closing this shell or losing
`source_bin`. Do not create an unrelated Profile to reach recovery, and do not
blindly retry the original edit/delete/rename.

Recovery aborts recognized preparation before a decision; after a decision it
rolls forward or preserves evidence and fails. It is not an undo or a historical
receipt: success with no pending transaction cannot prove what an earlier lost
response meant. Unknown journal versions, malformed metadata, unsafe paths,
unexpected links, outside interference or sync failures may remain blocked.
Retain the original files and error category for investigation. Copying a journal
elsewhere does not preserve its inode/link proof or authorize replay there.

The stationary `.profile-transaction-lock` in `~/.acs/profiles` is permanent.
An in-use error means kernel ownership is still held; even a stopped live process
keeps it. Wait for the actual owning operation to finish, then retry supported
recovery. Never delete, replace, rename or reclaim the lock, and never remove
`.profile-transaction-*` artifacts to bypass an error. Read the
[transaction contract](profile-repository-transactions.md) for its filesystem
limits; process-interruption tests do not prove arbitrary-volume power-loss safety.

## Recover a named Codex identity without exposing credentials

Named identities are versioned macOS Keychain records under ACS's service,
separate from Profile JSON. A filesystem backup of `~/.acs` does **not** export
these credentials. The records request non-synchronizable,
when-unlocked-this-device-only storage; do not treat them as portable files.
Locked, unavailable, ambiguous or corrupt Keychain state fails closed without a
plaintext fallback. Restore normal Keychain access through supported macOS
interfaces and retry; preserve evidence if schema or record integrity is rejected.

Use the [recovery-shell setup above](#recover-a-profile-transaction-with-compatible-development-source)
and initialize `source_bin` there even if you only need identity recovery.
With that compatible source binary, metadata-only listing is safe inspection:

```sh
"$source_bin" codex auth list
```

This queries non-secret attributes, not credential payloads, but names and account
metadata can still be private. It is not a quarantine-clearance test. `auth status`
is an active contained probe that can refresh an identity; it is not passive
inspection. Login/status require the supported `codex-cli 0.149.1` and native
sandbox. Recovery uses the stored proof and does not need a new Codex login.

After allowing the owning operation and contained descendants to settle, request
recovery for the exact affected name:

```sh
"$source_bin" codex auth recover --name work
```

The command acquires that identity's lock, validates quarantine and proves the
protected Session inactive. A `prepared` projection can only be discarded; an
inactive `cleanup_pending` projection also needs the supervisor's valid cleanup
proof. An unlocked lease alone is insufficient. Recovery can commit a refresh
only if the successful status operation recorded refresh eligibility and the
projected credential remains valid for the same method, workspace and identity.
Otherwise it discards the projection without deleting the last valid durable
identity. It removes the protected Session before clearing the identity marker.
An already absent marker is idempotent success; a missing Session from completed
cleanup is treated as already discarded.

An active lease, missing proof, changed marker generation or invalid protected
state keeps the identity blocked. Recovery may wait for the exact recoverable
generation's lock handoff; cancellation ends that wait without authorizing cleanup.
If supported recovery still refuses, leave the identity lock, pending projection,
Session lease, proof and quarantine markers in place. Preserve the compatible
binary and sanitized error for maintainer investigation. Never delete a Session
directory by name, clear quarantine manually, or use logout as a recovery bypass.
Logout refuses quarantined names. Generic abandoned-Session cleanup is not a
substitute for the owning authentication recovery proof.

For a retained Devin or sandbox-shell Session, allow the original owner to finish
its settlement/cleanup. There is no public `session recover` command or supported
manual deletion recipe. Keep unresolved evidence when settlement cannot be proven.

ACS never imports, changes or falls back to global `~/.codex/auth.json` or the
global Codex OS-store namespace. Do not copy global authentication into ACS or
into a Session as a repair. Do not dump Keychain secrets, projected `auth.json`,
Session contents or proof files into a terminal, issue, PR or support artifact.
Deleting/restoring a Profile does not delete/restore an identity. See the
[authentication contract](codex-auth.md) for the complete isolation boundary.

## Leave the recovery shell

After completing or pausing recovery and preserving any unresolved evidence,
leave this recovery shell with an explicit successful shell status. This keeps
the strict maintenance parent open even if your last inspection failed; it does
not mark that inspection or recovery successful.

<!-- example: recovery-exit -->
```sh
exit 0
```

## Validation boundary

The shell examples can be exercised with private temporary homes, fake downloads
and executables, including directories with spaces, verification failures,
command shadowing, old/new selection and rollback. Such checks establish shell
behavior and file preservation, not a real-user upgrade or recovery. Existing
installer tests cover no-overwrite, unsafe destinations, checksum/version failures
and archive validation. Native PR CI on macOS 26 arm64 and Intel remains necessary
for the installed candidate, filesystem transactions, Session settlement, Seatbelt
and disposable-Keychain recovery contracts. Its source candidate is not evidence
that the older published binary contains newer commands. No real credentials or
user-state migration is required for these checks, and no release publication is
part of this guide.

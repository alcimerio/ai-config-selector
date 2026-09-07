# Candidate migration and rollback guide

This guide prepares an unnumbered development candidate for daily-use
evaluation. It does not announce a release. The operator must supply the exact
candidate version embedded in the artifact, artifact directory, binary checksum,
and previously trusted executable. Do not substitute a guessed release URL,
`latest`, or a checksum copied from another build.

The supported candidate target is macOS 26 on Apple Silicon (`darwin/arm64`).
The immutable published v0.4.0 release remains available for both Apple Silicon
and Intel as historical evidence; that fact does not extend Intel support to the
candidate. See the [v0.4.0 release notes](releases/v0.4.0.md) and the
[release-pinned v0.4.0 maintenance procedure](manual-upgrade-recovery.md).

## Know which binary owns each capability

| Capability or stored state | Published v0.4.0 | Candidate built from current source |
| --- | --- | --- |
| `version`, Devin Profile creation/launch, sandbox shell | Supported | Supported |
| Profile envelope v1 and v2 | Read and launch as historical Devin Profiles | Read; explicit migration remains optional |
| Profile envelope v3 and common Devin/Codex overlays | Not supported | Supported |
| `profile list/show/validate`, mutations and transaction recovery | Not available | Supported |
| Declarative v3 creation and portable exchange v1 | Not available | Supported |
| Bounded local Profile history | Not available | Supported after a Profile is adopted by a successful mutation |
| Literal contained `run` and effective-authority explanation | Not available | Supported |
| Named Codex authentication and durable Session operations | Not available | Supported |

Installing or selecting a binary never migrates data. Passive Profile inspection
never rewrites a Profile. A confirmed current-source mutation can canonicalize a
legacy Profile as v2, while only `acs profile migrate NAME` deliberately adopts
the v3 common format. Migration preserves legacy workspace write authority
explicitly; changing it to read-only is a separate operator choice. Adding a
Codex overlay and named authentication is also separate.

Version 3 Profiles use independently versioned common Skills/workspace data and
supported target overlays. Portable exchange version 1 carries sanitized v3
intent and symbolic local bindings, not local persistence. Profile transaction,
history, Session and Keychain formats have their own lifecycle rules; a Profile
schema number says nothing about their compatibility. Read the
[common Profile contract](common-profile-format.md),
[portable exchange contract](portable-profile-exchange.md),
[history boundary](profile-history.md), and
[Session recovery contract](session-operations.md) before changing state.

## Supply, install and verify the exact candidate

Obtain the promoted candidate directory and all values below through the
approved artifact handoff. The directory must contain exactly the supplied
candidate's `install.sh`, `SHA256SUMS`, and Apple Silicon archive. Work from a
clean checkout of the same source revision as the candidate; the validator is a
repository maintenance interface, not a downloadable release channel.

Start a dedicated Bash with `/bin/bash --noprofile --norc`. Then export the
operator-supplied values; the example intentionally provides no defaults:

<!-- candidate-example: inputs -->
```sh
set -eu
umask 077
: "${ACS_CANDIDATE_VERSION:?supply the candidate embedded version}"
: "${ACS_CANDIDATE_DIR:?supply the absolute promoted artifact directory}"
: "${ACS_CANDIDATE_ARCHIVE_NAME:?supply the exact Apple Silicon archive name}"
: "${ACS_CANDIDATE_ARCHIVE_SHA256:?supply the verified archive SHA-256}"
: "${ACS_CANDIDATE_MANIFEST_SHA256:?supply the verified SHA256SUMS SHA-256}"
: "${ACS_CANDIDATE_INSTALLER_SHA256:?supply the verified installer SHA-256}"
: "${ACS_CANDIDATE_BINARY_SHA256:?supply the verified installed binary SHA-256}"
: "${ACS_KNOWN_GOOD_BIN:?supply the absolute trusted current executable}"
: "${ACS_MAINTENANCE_ROOT:?supply a new absolute private maintenance directory}"

candidate_version="$ACS_CANDIDATE_VERSION"
candidate_dir="$ACS_CANDIDATE_DIR"
candidate_archive_name="$ACS_CANDIDATE_ARCHIVE_NAME"
candidate_binary_sha256="$ACS_CANDIDATE_BINARY_SHA256"
known_good_bin="$ACS_KNOWN_GOOD_BIN"
maintenance_root="$ACS_MAINTENANCE_ROOT"
candidate_bin="$maintenance_root/candidate/bin"
rollback_bin="$maintenance_root/known-good/bin"
path_before_candidate="$PATH"

case "$candidate_dir:$known_good_bin:$maintenance_root" in
  /*:/*:/*) ;;
  *) exit 1 ;;
esac
test -d "$candidate_dir"
test ! -L "$candidate_dir"
case "$candidate_archive_name" in
  "" | */* | .* | *[!A-Za-z0-9._-]*) exit 1 ;;
esac
test -f "$candidate_dir/$candidate_archive_name"
test ! -L "$candidate_dir/$candidate_archive_name"
test -f "$candidate_dir/SHA256SUMS"
test ! -L "$candidate_dir/SHA256SUMS"
test -f "$candidate_dir/install.sh"
test ! -L "$candidate_dir/install.sh"
test -f "$known_good_bin"
test ! -L "$known_good_bin"
test -x "$known_good_bin"
mkdir "$maintenance_root"
chmod 0700 "$maintenance_root"
mkdir "$maintenance_root/candidate" "$maintenance_root/known-good"
mkdir "$rollback_bin"
printf '%s  %s\n%s  %s\n%s  %s\n' \
  "$ACS_CANDIDATE_ARCHIVE_SHA256" "$candidate_archive_name" \
  "$ACS_CANDIDATE_MANIFEST_SHA256" SHA256SUMS \
  "$ACS_CANDIDATE_INSTALLER_SHA256" install.sh \
  > "$maintenance_root/candidate/supplied-files.sha256"
(
  cd "$candidate_dir"
  shasum -a 256 -c "$maintenance_root/candidate/supplied-files.sha256"
)
cp -p "$known_good_bin" "$rollback_bin/acs"
cmp "$known_good_bin" "$rollback_bin/acs"
"$rollback_bin/acs" version > "$maintenance_root/known-good/version.txt"
(
  cd "$rollback_bin"
  shasum -a 256 acs > "$maintenance_root/known-good/SHA256SUMS"
)
```

Run the repository validator from the candidate's exact clean source checkout.
It verifies the artifact set, target identity, release-specific installer,
custom and default installation behavior, exact archive selection, installed
version, and temporary cleanup. It refuses a non-Apple-Silicon host.

<!-- candidate-example: install -->
```sh
scripts/validate-promoted-artifact.sh \
  "$candidate_version" darwin arm64 "$candidate_dir" "$candidate_bin"
printf '%s  acs\n' "$candidate_binary_sha256" \
  > "$maintenance_root/candidate/binary.sha256"
(
  cd "$candidate_bin"
  shasum -a 256 -c "$maintenance_root/candidate/binary.sha256"
)
"$candidate_bin/acs" version > "$maintenance_root/candidate/version.txt"
printf 'acs %s\n' "$candidate_version" \
  > "$maintenance_root/candidate/expected-version.txt"
cmp "$maintenance_root/candidate/expected-version.txt" \
  "$maintenance_root/candidate/version.txt"
```

Stop on any failure. A matching version string alone cannot distinguish two
builds. Retain the private candidate directory, supplied provenance, checksum,
source commit and tree, validator output, and installed-binary checksum together.
Do not strip quarantine, disable Gatekeeper, ad-hoc sign, or weaken Seatbelt to
make a candidate run.

## Check compatibility before writing

Select the candidate only in the maintenance shell. This does not edit startup
files or affect existing processes.

<!-- candidate-example: compatibility -->
```sh
export PATH="$candidate_bin:$path_before_candidate"
hash -r
test "$(command -v acs)" = "$candidate_bin/acs"
acs version
acs doctor
acs profile list
acs profile show backend-review
acs profile validate backend-review
acs session list
```

Read every result. `doctor` and the Profile commands above are passive, and
`session list` does not prove active owners have settled. Nonzero can mean a
missing Profile, invalid or unsupported stored structure, unavailable selected
Skill source, host failure, or corrupt lifecycle evidence; it is not permission
to migrate, delete, retry, or restore. Keep the known-good and candidate binaries
until every stored format and pending operation has a compatible owner.

Before a deliberate Profile write, finish live editors and contained work, settle
or recover pending operations through their owning binary, and make the private
quiescent Profile-byte copy described in the
[maintenance guide](manual-upgrade-recovery.md#binary-rollback-is-not-a-data-downgrade).
That copy is not portable exchange, transaction evidence, history, or a backup of
Skills, Sessions, target state, or credentials.

## Preview and explicitly migrate one legacy Profile

Run migration only for a legacy Profile you intend to adopt. The interactive
preview shows schema fields, exact canonical bytes, retained workspace authority,
and changed common/target material paths before asking for confirmation:

<!-- candidate-example: migrate -->
```sh
acs profile migrate backend-review
```

Cancel at the preview to make no decision, or confirm the displayed exact result.
Cancellation and ordinary pre-commit failure leave the prior bytes unchanged.
After confirmation, heed `not committed`, `committed`, `unknown`, and
`recovery required` literally. Do not blindly retry an unknown outcome.

After a confirmed migration, inspect the stored v3 Profile and optionally create
a sanitized exchange document. Export does not include Skill contents, resolved
paths, history, Sessions, or authentication:

<!-- candidate-example: after-migrate -->
```sh
acs profile show backend-review
acs profile validate backend-review
acs profile export backend-review --file backend-review.acs-profile.json
acs profile import validate --file backend-review.acs-profile.json
```

The no-overwrite export file belongs outside a repository or shared directory if
its logical intent is private. Import elsewhere requires explicit local bindings
and checks structure, not actual Skill/auth/target readiness.

## Recover after interruption

For inspection after an expected nonzero result, start a separate recovery Bash
with an explicit candidate-directory handoff:

<!-- candidate-example: recovery-shell -->
```sh
ACS_RECOVERY_CANDIDATE_BIN="$candidate_bin" /bin/bash --noprofile --norc
```

In that new shell, disable inherited exit-on-error and derive the executable only
from the required handoff:

<!-- candidate-example: recovery -->
```sh
set +e
: "${ACS_RECOVERY_CANDIDATE_BIN:?missing candidate binary directory}"
candidate_acs="$ACS_RECOVERY_CANDIDATE_BIN/acs"
"$candidate_acs" profile list
"$candidate_acs" profile show backend-review
"$candidate_acs" devin create-profile --name backend-review
"$candidate_acs" profile list
"$candidate_acs" profile show backend-review
exit 0
```

The creation entry point settles a pending Profile repository transaction before
its duplicate-name check. If the Builder opens, cancel it without saving. Exit
130 does not reverse recovery already completed. Explicit `exit 0` returns to a
strict parent without relabeling a failed inspection as success.

Use `acs session inspect ID` and `acs session recover ID` only for the exact
sanitized Session ID reported by ACS. Named authentication uncertainty uses
`acs codex auth recover --name NAME`. Both paths require their private generation,
inactive lease and valid cleanup proof; neither kills a process or accepts force.
Never delete locks, journals, Session roots, proofs, quarantine, or Keychain
records manually, and never copy global Codex authentication into ACS.

## Roll back the executable, not the data

This block verifies and selects the retained executable in the maintenance shell:

<!-- candidate-example: rollback -->
```sh
(
  cd "$rollback_bin"
  shasum -a 256 -c "$maintenance_root/known-good/SHA256SUMS"
)
export PATH="$rollback_bin:$path_before_candidate"
hash -r
test "$(command -v acs)" = "$rollback_bin/acs"
acs version > "$maintenance_root/rollback-version.txt"
cmp "$maintenance_root/known-good/version.txt" \
  "$maintenance_root/rollback-version.txt"
```

Rollback changes only command selection. It does not downgrade Profile v3,
history, exchange files, Session records or named authentication. Published
v0.4.0 cannot inspect or safely own those current-source formats. After the
candidate has written newer state, use the candidate for inspection and
supported recovery even if routine command selection returns to an older binary.
Never overwrite newer live state with an older Profile copy as routine rollback.

Local Profile history is bounded recovery for supported Profile configuration.
It does not restore external Skill files, target state, Session state, credentials,
or deleted machine data, and it is not a full backup. A history restore decodes
through the current codec and can require explicit current-machine bindings.

## One-week daily-use observation (unperformed)

The candidate is not release-ready merely because automated gates pass. Complete
this template on two real project contexts without recording private content.
Automated Codex evidence uses the official checksum-locked CLI, synthetic
authentication and a local simulated API; it is not hosted inference or a real
account observation.

```text
Observation status: UNPERFORMED / PENDING
Start and end dates (timezone):
Project aliases (two; no paths, repository names or private content):
Source commit and tree:
Candidate embedded version, artifact SHA-256 and installed binary SHA-256:
Target: macOS 26 darwin/arm64
Devin and Codex versions:
Useful-work quickstart result and elapsed time:
Profile schema before/after; migration decision and outcome:
Shared Skills identities (source:relativePath only) and target projections:
Named Codex auth isolation observed (no account or credential data):
Workspace read-only/read-write behavior and unrelated-path denial:
Terminal input/output, resize, interrupt and descendant settlement:
Session cleanup or exact sanitized recovery result:
Two real project contexts used on each date:
Blockers and public result categories:
Release decision: PENDING
```

Do not fabricate elapsed days, hosted inference, accounts, project work, cleanup,
or success. Final release version substitution, artifact selection, signing and
notarization posture, native installed-artifact validation, and completion of the
observation remain final-cut dependencies.

Related tracking remains open in
[#102](https://github.com/alcimerio/ai-config-selector/issues/102),
[#104](https://github.com/alcimerio/ai-config-selector/issues/104), and
[#105](https://github.com/alcimerio/ai-config-selector/issues/105). This
preparation guide does not complete their release-artifact or real-use evidence.

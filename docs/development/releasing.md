# Release and candidate verification

[Documentation index](../README.md) · [Testing](testing.md) · [Contributing](../../CONTRIBUTING.md)

## Release preparation

Release tags are immutable and created only after the release-preparation PR is
merged to protected `main`.

Before preparing a version, merge its release notes at
`docs/releases/vMAJOR.MINOR.PATCH.md`; the tag validation and publication scripts
consume that exact file. Keep current notes there, and use immutable GitHub
Releases and Git history for older release records rather than adding rolling
checklists or handoff ledgers to the documentation tree.

Verify the exact reviewed source, annotated tag identity, notes and required
checks. Obtain explicit authorization for the tag push: it starts the automatic
build, native validation, attestation and immutable publication pipeline with no
later approval pause.

For a future release (using `v1.2.3` as an example), first merge its release
notes and preparation changes. From a clean `main` checkout, fetch and confirm
that `HEAD` is the reviewed `origin/main` commit, then prepare the local tag:

```sh
git fetch origin main
scripts/prepare-release-tag.sh v1.2.3
```

The preparation script requires `main` to match the fetched `origin/main`,
refuses an existing local or remote tag, runs `scripts/release-candidate.sh`,
and prints the source commit and annotated tag-object identity. Review those
identities and obtain authorization before separately running:

```sh
git push origin refs/tags/v1.2.3
```

For a standalone local artifact check without creating a tag, run
`scripts/release-candidate.sh v1.2.3`. It requires a clean worktree and places
exactly these files in `dist/release-candidate/`:

```text
acs_1.2.3_darwin_arm64.tar.gz
SHA256SUMS
install.sh
```

The tag workflow validates annotated tag identity and ancestry, builds the
candidate once after a tagged-source vulnerability scan, installs the exact bytes
on the native Apple Silicon target, scans that installed binary, runs normal,
race, and black-box acceptance tests, attests the archive and
checksum manifest, and publishes through the protected `release` environment.

Never move or delete a release tag. If a candidate fails, fix the source in a
new commit and prepare a new version. Do not treat a local build or authenticated
smoke as a replacement for the native Apple Silicon artifact gate.

Verify the published asset hashes against the build-once candidate and verify
GitHub attestations for the archive and checksum manifest. The installer is
byte-matched to the artifact set but is not an attestation subject. Record the
source/tag identities, workflow run and sanitized results in the release PR or
GitHub Release. Checksums and provenance do not provide Apple signing,
notarization, malware review or Gatekeeper approval. Never strip quarantine,
disable Gatekeeper, ad-hoc sign or weaken Seatbelt to make a release run.

## Test a development candidate

A development version string does not identify published release bytes. Obtain
the exact artifact set and trusted digests from its approved workflow handoff,
and use the matching clean source checkout. Record the actual CI source and
merged source separately; equal trees do not change build provenance. An expired
artifact must be replaced by a newly identified build, not rebuilt under its old
identity. The validator is a repository maintenance tool, not a release channel.

Start `/bin/bash --noprofile --norc` on a supported Mac. Supply all inputs below:
the directory must contain only `install.sh`, `SHA256SUMS` and the named Apple
Silicon archive. Use a new private, absolute, direct maintenance directory outside
repositories or shared folders. The known-good binary must already be trusted.
These blocks run in order in that shell; `set -e` stops on a failed check.

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
: "${ACS_CANDIDATE_BINARY_SHA256:?supply the archive-member SHA-256; verify installed bytes below}"
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

The validator checks the target, exact artifact set, release-specific installer,
custom/default installation behavior, version and cleanup. Verify the installed
binary separately: an archive-member digest is only an expected value until the
host comparison succeeds.

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

Stop on any mismatch and preserve the evidence. Keep the known-good and candidate
binaries until every stored format and pending operation has a compatible owner.
Select the candidate only in this shell, then inspect before making changes.
Replace `backend-review` with an existing name from `profile list`; if the store
is empty, omit the `profile show` and `profile validate` lines. Do not create a
Profile just to perform these passive checks.

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

These checks are passive. A nonzero status is not permission to migrate, delete,
restore or retry; Session listing does not prove active owners have settled.
Before a confirmed write, settle operations and make a private quiescent copy of
Profile bytes. Follow the
[migration and recovery steps](../guides/manual-upgrade-recovery.md#binary-rollback-is-not-a-data-downgrade)
for Profile format compatibility, preview cancellation and interrupted operations.

To select the retained executable again in the same maintenance shell:

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

This changes command selection only, not startup files, existing processes or
stored data. If the strict shell exited, use the retained binary's explicit
absolute path instead of rerunning the new-directory setup. An older executable
may not understand newer Profiles, history, Sessions or named identities; keep
the owning compatible binary for recovery. Never overwrite newer live state with
an old backup or manually remove locks, journals, Session state or quarantine.

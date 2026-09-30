# Contributing

ACS supports macOS 26 on Apple Silicon (`darwin/arm64`). Linux/Bubblewrap source
is retained, but Linux failures are not release blockers and do not imply a
support promise. Intel Macs are not a supported runtime or release target.

## Local setup

Install Go 1.25 or later, clone the repository, and run these checks on a
supported Apple Silicon Mac:

```sh
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/acs
```

Run formatting before committing:

```sh
gofmt -w path/to/changed.go
```

Do not commit generated `dist/` content, credentials, Session data, captured
target output, private paths, environment values, or generated Seatbelt policy.

## Development rules

- Add a failing test before changing behavior.
- Keep public CLI parsing in `internal/cli` and target behavior behind planner
  and launcher boundaries.
- Keep common Profile codecs, defaults, authority and materialization in
  `internal/commonprofile`, and the immutable execution inputs in
  `internal/authority`. Target adapters may provide only fixed projection and
  declarative target requirements. The shared executor owns backend selection,
  executable/runtime verification, Sessions, processes and cleanup. Typed
  authentication resources remain separate.
- Do not add a backend selector, sandbox bypass, unsandboxed fallback, arbitrary
  shell command option, or `$SHELL` lookup.
- Preserve stable error categories and sanitize private backend detail.
- Treat cleanup proof as part of correctness. Never delete a Session while its
  contained process tree may still be alive.
- Preserve existing version-1 and version-2 Profile behavior unless an explicit
  migration is designed and documented.

## Testing the sandbox shell

The main contract is:

```sh
acs sandbox --profile PROFILE --dry-run
acs sandbox --profile PROFILE
```

The interactive target must remain exactly `/bin/zsh -f`. Tests should cover:

- selected Skills in the synthetic home;
- absence of the Devin credential and Devin preflights;
- workspace, Session home, and Session temporary writes;
- denial of unrelated host reads/writes and symlink escapes;
- clean environment and descriptor behavior;
- terminal input/output, resize, signals, and exit status;
- descendants and Session cleanup after every exit path;
- stable fail-closed errors before and after Session creation.

Native Seatbelt tests can fail when run inside another restrictive sandbox.
Run them from a normal macOS terminal when validating production behavior:

```sh
go test ./internal/launch ./internal/sandboxshell -count=1
go test -race ./internal/launch ./internal/sandboxshell -count=1
```

Do not weaken macOS security settings to make a test pass.

## Linux source

The retained Linux implementation may be cross-compiled as a non-blocking
observation. From the repository root, write each architecture's test binaries
to a separate temporary directory without executing them:

```sh
(
  set -eu
  compile_dir="$(mktemp -d "${TMPDIR:-/tmp}/acs-linux-compile.XXXXXX")"
  trap 'rm -rf "$compile_dir"' EXIT
  mkdir "$compile_dir/amd64" "$compile_dir/arm64"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o "$compile_dir/amd64/" ./...
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o "$compile_dir/arm64/" ./...
)
```

`-c` is compile-only. `go test -run '^$'` still starts each test executable
(and its package initialization), so it is not a cross-compilation-only check
on macOS. Neither this check nor the native Linux CI observation proves Linux
runtime support.

Do not publish Linux archives, add Linux native release jobs, or describe Linux
as supported without a separate decision that restores ownership and evidence
for that platform.

## Native named-authentication evidence

The promoted-artifact PR workflow fetches the official Apple Silicon
`codex-cli 0.149.1` archive once, verifies its reviewed SHA-256 lock entry, and
installs that native target on macOS 26. Its opt-in native
tests use a disposable Keychain and synthetic home and require the real
Seatbelt path; they use no account credentials and emit no target, account,
device, keychain, home, Session, or credential content.

For a local credential-free run, first use
`scripts/fetch-codex-test-targets.sh` and
`scripts/install-codex-test-target.sh`, then set
`ACS_RUN_NATIVE_AUTH_GATE=1` and point `ACS_TEST_CODEX_BINARY` at that verified
native installation. Also set `ACS_NATIVE_AUTH_RECOVERY_ROOT` to a deterministic
private path, and run the separate `TestNativeKeychainRecoveryEntrypoint`
invocation afterward even when the native test invocation fails. The promoted
workflow's shared `scripts/run-native-candidate-gates.sh` does this in its
exit/signal cleanup trap on the native Apple Silicon runner. A hard runner
termination can prevent that trap from running; retain recovery evidence when
cleanup was not observed.
Run these focused tests only from a normal macOS terminal. The
automated gate proves the isolated Keychain contract and contained status
lifecycle; it does not prove interactive login completion or target-origin
token refresh. Production Keychain queries prohibit authentication UI, and
deterministic error-mapping tests cover locked or unavailable providers. Live
locked-Keychain and direct ACL probes remain supplemental because macOS can
present access-control UI for those operations.

## Optional authenticated smoke

Authenticated Devin and Codex checks are supplemental observations. They must
not run in CI, use a shared account, or replace the credential-free native gate.
Use a trusted macOS 26 Apple Silicon host and a normal terminal, with terminal
recording, shell tracing, debug logging and output capture disabled. Install the
exact reviewed candidate as described below; use verified, locked target binaries.

- **Devin:** start with an already authenticated CLI. A normal Profile launch
  may copy its existing credential into an ephemeral Session. Observe sandbox,
  Skill and authentication preflight, the interactive lifecycle, return to the
  terminal, and absence of a leased Session after exit.
- **Codex:** use a dedicated test account and a clean disposable identity name
  with no quarantined Session. Run browser or device login, then contained
  status. Observe target-origin token refresh only if it happens naturally;
  never force, inject, copy, decode, compare or print tokens. Remove the identity
  with ACS logout and check that no leased Session or quarantine remains.

If cleanup is uncertain, retain the compatible ACS binary and private evidence
and use the [recovery guide](docs/manual-upgrade-recovery.md). Do not delete
Session or Keychain state by hand, use logout to bypass quarantine, copy global
Codex authentication, weaken Seatbelt, or bypass a native trust failure.

Record only source commit, artifact and installed-binary digests, target version
and locked digest, host architecture, command category, and pass/fail or not
observed. Account identifiers, device codes, browser URLs, target output,
credentials, token timestamps, Keychain contents, homes, Sessions, private paths,
environment values and generated policy must not be recorded. A smoke does not
prove reproducibility, release immutability, deterministic account behavior or
sustained real-project use. Record the actual duration and scope of any separate
daily-use observation; never infer it from automated or publication success.

## Research harnesses

Opt-in extension discovery and hook fixtures test target-owned behavior through
synthetic authentication and local simulators. They do not add ACS-managed
plugins, hooks or agents, prove hosted inference, or establish detached-child
cleanup beyond the tested containment contract. Run the portable fixtures with
`go test ./internal/extensionassessment`. The
[promoted-artifact workflow](.github/workflows/promoted-artifacts.yml) contains the separate locked-target invocation of
`TestPromotedArtifactNativeDevinSessionStartHook`; do not fold it into the
mandatory release gate or use account credentials in it.

The [native transport probes](docs/native-transport-research.md) run on a
disposable macOS runner and preserve bounded transport evidence. They do not
change runtime policy or establish destination-specific network enforcement.
Keep test fixtures and workflow evidence distinct from production feature claims.

## Pull requests

Before opening a PR:

1. Run formatting, vet, normal tests, and race tests on macOS.
2. Run the native sandbox-shell test from a normal terminal.
3. Inspect `git diff --check` and the complete diff.
4. Explain the user-visible contract and the tests that prove it.
5. Confirm that no release asset, tag, or external state is changed by the PR.

The PR gates install the candidate bytes on macOS 26 Apple Silicon. The native
job must pass before merge. The Linux compile observation is explicitly
nonblocking.

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
candidate once, installs the exact bytes on the native Apple Silicon target,
runs normal, race, and black-box acceptance tests, attests the archive and
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
Profile bytes. Follow the [migration and recovery steps](docs/manual-upgrade-recovery.md#binary-rollback-is-not-a-data-downgrade)
for explicit Profile migration, preview cancellation and interrupted operations.

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

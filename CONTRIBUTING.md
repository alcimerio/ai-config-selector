# Contributing to AI Config Selector

Thanks for contributing to AI Config Selector (ACS).

## Before you start

ACS currently supports macOS, Linux, and the Devin CLI. Read
[`docs/architecture.md`](docs/architecture.md) before changing Profile,
Session, discovery, isolation, or launch behavior.

Open a GitHub issue before starting a feature, architecture change, or large
refactor. Small bug fixes and documentation corrections may go directly to a
pull request. Keep each pull request focused on one problem.

## Local setup

Install Go 1.25 or later, clone the repository, and run:

```bash
go test ./...
go build ./cmd/acs
```

ACS can create files under `~/.acs` and launch an installed target CLI. Use
temporary homes, fake target binaries, or test fixtures while developing. Do
not point tests at a user's real global Skill directories or credentials.

### Opt-in real-Devin integration test

The normal test suite does not invoke a real Devin installation. Maintainers
can run the adapter contract against the installed CLI explicitly:

```bash
ACS_REAL_DEVIN_INTEGRATION=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS \
  go test -tags=integration ./internal/adapter/devin
```

This opt-in test requires macOS or Linux, an installed Devin CLI, and an
authenticated Devin account. It reads the existing authenticated state. The
build tag alone is insufficient; the exact environment value records an
explicit local acknowledgement. Run it only when the machine owner has agreed
to that access. `go test ./...` and all pull-request and `main` workflows remain
credential-free.

## Development guidelines

- Preserve the configuration-isolation boundaries and invariants documented
  in the architecture.
- Keep shared Profile and launch behavior independent of target-specific paths.
- Add regression tests for behavior changes and bug fixes. Prefer public seams
  such as the Profile Store and CLI application over private helpers.
- Keep terminal output free of raw control characters from discovered names,
  paths, subprocess output, or errors.
- Update `docs/architecture.md` when a change alters observable behavior or a
  system boundary.

Format and verify the change before opening a pull request:

```bash
go fmt ./...
go vet ./...
go test ./...
git diff --check
```

## Release validation

Release packaging uses GoReleaser OSS v2.17.1. The repository wrapper downloads
that exact version, verifies the official binary checksum for the validation
host, and rejects unsupported validation hosts. From a clean Git worktree,
check the configuration, build all four snapshot archives, and inspect the
candidate artifact set with:

```bash
scripts/goreleaser.sh check
scripts/release-candidate.sh v0.2.0
```

The candidate command disables CGO, builds only the supported Darwin and Linux
amd64 and arm64 targets, stages the four archives and `SHA256SUMS` under
`dist/release-candidate/`, and validates their names, checksums, top-level
contents, executable mode, and locally runnable packaged version. It does not
create a tag or GitHub Release. Use the intended canonical tag for the
candidate; the command does not accept development, prerelease, build-metadata,
or dirty source input.

The candidate set also contains one executable `install.sh` rendered with the
same immutable tag. Installer acceptance uses fake host and download tools plus
local archives; it never contacts a GitHub Release or writes to a real user
installation. Run it with the normal test suite, or focus it with:

```bash
go test ./scripts -run Installer
```

The supported installer interface accepts only an optional `--bin-dir` and has
no version override. Tests cover exact Release URLs, all supported targets,
checksum and archive rejection, destination safety, executable validation,
atomic placement, PATH guidance, and cleanup.

Pull requests and `main` also build one complete candidate set and transfer
those exact workflow-artifact bytes to four native jobs: darwin/arm64,
darwin/amd64, linux/amd64, and linux/arm64. Each job rejects a host whose
operating system or architecture does not match its required target, runs the
normal credential-free application, Adapter, installer, race, and PTY suites,
then installs and exercises the candidate executable as a black box. The
acceptance harness uses only a synthetic home, a fake Devin executable, and
temporary install and Session directories. It does not read real Devin
credentials or modify a maintainer installation.

After building a clean candidate locally, run the validator on a matching
native host with a fresh absolute install directory:

```bash
install_root="$(mktemp -d)"
install_root="$(cd "$install_root" && pwd -P)"
scripts/validate-promoted-artifact.sh \
  v0.2.0 "$(go env GOOS)" "$(go env GOARCH)" \
  dist/release-candidate "$install_root/bin"
ACS_PROMOTED_BINARY="$install_root/bin/acs" \
  ACS_PROMOTED_VERSION=v0.2.0 \
  go test ./acceptance -count=1
```

The native target validator preserves the installer's exact pinned GitHub
Release URLs while serving the supplied bytes through a controlled local
download tool. It verifies the complete candidate set, selected archive,
checksum, structure, executable mode, version, custom and default destination
behavior, PATH guidance, and cleanup. Cross-compilation and emulation are not
native evidence. If any required runner is unavailable or any native job
fails, the candidate is not promoted.

Before tagging a release, follow the
[authenticated release-candidate smoke procedure](docs/authenticated-release-smoke.md)
on macOS 26 arm64 and a disposable Ubuntu 24.04 amd64 host. It installs the
exact candidate archives, exercises the visual Profile and interactive Devin
boundaries, verifies Session isolation and cleanup, and produces strict,
candidate-matched sanitized evidence for later release review. A missing host,
authorization, or passing evidence remains a blocking release gate.

The release tag is an annotated canonical SemVer tag. Its complete annotation
is the strict evidence-set JSON envelope containing exactly one macOS 26 arm64
record and one Ubuntu 24.04 amd64 record. Both records must name the tagged
commit and the exact archive and `SHA256SUMS` bytes rebuilt by the tag workflow.
The source tree must also contain nonempty release notes at
`docs/releases/<tag>.md`. Do not create the tag until those inputs are final.

Before the tag is pushed, enable the repository's immutable Releases setting
and create two active tag rulesets covering exactly `refs/tags/v*`. The first
must restrict updates and deletions with no bypass actors. The second must
restrict creation and allow only the designated release maintainers to bypass
that creation rule. Record their numeric IDs in the
`ACS_RELEASE_TAG_RULESET_ID` and `ACS_RELEASE_TAG_CREATION_RULESET_ID`
repository variables. The creation ruleset must have exactly one `User` bypass
actor in `always` mode; record that user's numeric ID as
`ACS_RELEASE_TAG_CREATOR_ID`. The tag-triggering actor must match that ID.

Configure a protected `release` environment with required reviewers and no
self-review. Install two repository-only GitHub Apps so no credential can both
change policy and publish a Release. The policy App needs
Administration(write), because GitHub omits ruleset bypass actors from weaker
tokens; store its client ID as `ACS_RELEASE_POLICY_APP_CLIENT_ID` and its key as
the `ACS_RELEASE_POLICY_APP_PRIVATE_KEY` environment secret. The publication
App needs only Contents(write); store its client ID as
`ACS_RELEASE_PUBLISH_APP_CLIENT_ID` and its key as the
`ACS_RELEASE_PUBLISH_APP_PRIVATE_KEY` environment secret. The workflow uses
short-lived installation tokens only after environment approval and does not
accept a personal access token. The tagged commit must be contained in the
current protected `main` history.

The tag workflow builds once, transfers those bytes through all four
native jobs, attests the four archives and checksum manifest, and only then
creates or resumes a draft Release. It uploads only missing assets whose names
are in the exact Release Artifact Set and rejects conflicting assets or
metadata. A complete draft is made public with one final transition. A rerun
of the unchanged tag resumes a compatible draft or accepts the already
immutable, byte-identical Release; it never deletes, replaces, or rebuilds an
asset during publication.

If any gate fails, no public Release is created. Correct source, evidence,
notes, workflow configuration, tags, or artifact bytes with a new patch
version. Never move a published tag or replace a published asset.

After publishing the immutable tag, repeat the
installation from the module proxy in another clean temporary `GOBIN`:

```bash
tagged_gobin="$(mktemp -d)"
GOBIN="$tagged_gobin" go install github.com/alcimerio/ai-config-selector/cmd/acs@v0.1.0
"$tagged_gobin/acs" version
rm "$tagged_gobin/acs"
rmdir "$tagged_gobin"
```

The tagged installation must print `acs v0.1.0`. Do not move or reuse a
published tag; publish a new version to correct a release defect.

## Pull requests

Each pull request should:

- explain the problem and the behavior delivered;
- link the issue or discussion that defines the work, when one exists;
- describe compatibility or migration risks;
- list the exact validation commands that passed;
- include terminal output, screenshots, or a recording when interaction or
  presentation changes;
- identify macOS behavior that was tested and any relevant behavior that was
  not tested.

Keep the pull request title in Conventional Commit form. When squash-merging,
set the resulting commit subject to `<pull request title> (#<pull request
number>)` and verify that exact subject from the merged commit SHA.

Maintainers may ask to narrow, redesign, or split a contribution before
merging it.

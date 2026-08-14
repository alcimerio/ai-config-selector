# Contributing to AI Config Selector

Thanks for contributing to AI Config Selector (ACS).

## Before you start

The v0.2.0 release contract defines macOS 26 and Ubuntu 24.04 LTS as the
Supported Platforms. Its Supported Release Targets are `darwin/arm64`,
`darwin/amd64`, `linux/amd64`, and `linux/arm64`. Other Linux distributions,
Windows, WSL, and other target pairs are outside that contract. ACS supports
the Devin CLI on both Supported Platforms. Read
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

Release-related pull requests also run the complete locally applicable gate:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
go test ./...
if [ "$(go env GOOS)" = linux ]; then
  go test -race ./... -skip '^TestProfileBuilderPTYRestoresTerminal/(runtime_error|recovered_panic)$'
else
  go test -race ./...
fi
go build ./cmd/acs
for script in scripts/goreleaser.sh scripts/release-candidate.sh \
  scripts/prepare-release-tag.sh scripts/release-tag-identity.sh \
  scripts/validate-promoted-artifact.sh scripts/install.sh.tmpl; do
  sh -n "$script"
done
bash -n scripts/publish-release.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

The race-test skip is only for the documented third-party Linux cancelreader
shutdown race in the abrupt `runtime_error` and `recovered_panic` PTY cases.
The normal suite still exercises both cases, and macOS runs `go test -race
./...` without that exception. Also cross-build and cross-test-compile all four
Supported Release Targets and reconcile the final worktree. Native jobs, not
cross-compilation, provide promoted-artifact acceptance evidence.

### Ubuntu native-test remediation

Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor, so the
Ubuntu-native workflows install the targeted AppArmor
`bwrap-userns-restrict` profile for `/usr/bin/bwrap` before their native test
commands. Ubuntu Noble exposes this optional profile through
`apparmor-profiles`, but it is not enabled by default and its documented
compatibility may lag upstream. The workflows therefore use the pinned
AppArmor project v4.0.3 profile, verify its SHA-256
`a964037f6cf0df1099f14226b037eaedde6237c86e715188e93eb460b30be859`, install
it root-owned at `/etc/apparmor.d/bwrap-userns-restrict`, and load it with
`apparmor_parser`. They then execute a real `/usr/bin/bwrap` user-namespace
probe before running Go tests.

This remediation permits the targeted Bubblewrap profile only. It does not
set `kernel.apparmor_restrict_unprivileged_userns=0`, disable AppArmor, skip
native tests, or relax ACS's package-integrity and runtime capability checks.
Local Ubuntu-native validation needs the same reviewed profile setup; a failed
probe is an infrastructure failure, not evidence that the production sandbox
can run without containment.

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
credentials or modify a maintainer installation. Each target declares the
native sandbox capability expected at that release increment. The two macOS
targets require the installed launch to fail closed with
`backend_unavailable` before a Session is leased or the fake Devin process
starts. The two Ubuntu targets require the installed launch, signal,
terminal-resize, and concurrent-lease assertions to succeed through the
system Bubblewrap backend. Ubuntu-native tests additionally prove filesystem,
environment, descriptor, networking, descendant, and lifecycle containment.

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
  ACS_PROMOTED_SANDBOX_BACKEND=<available-on-ubuntu-or-unavailable-on-macos> \
  go test ./acceptance -count=1
```

The native target validator preserves the installer's exact pinned GitHub
Release URLs while serving the supplied bytes through a controlled local
download tool. It verifies the complete candidate set, selected archive,
checksum, structure, executable mode, version, custom and default destination
behavior, PATH guidance, and cleanup. Cross-compilation and emulation are not
native validation. If any required runner is unavailable or any native job
fails, the candidate is not promoted.

These four native jobs are the required runtime release gate. They install and
exercise the same candidate bytes that the workflow later attests and
publishes. A failing or unavailable native job blocks the release.

An authenticated smoke with real Devin is optional and risk-triggered. Run the
[authenticated release-candidate smoke procedure](docs/authenticated-release-smoke.md)
on the maintainer's macOS 26 arm64 host before the first release, or when a
change touches authentication, the Devin Adapter, Profile selection, Session
isolation, or interactive lifecycle behavior. It is a maintainer confidence
check, does not use CI credentials, and is not attached to the tag or workflow.

The release tag is an annotated canonical SemVer tag. The tag points to the
exact source commit and carries a short human-readable annotation. The source
tree must also contain nonempty release notes at `docs/releases/<tag>.md`. From
a clean, freshly fetched `main` whose `HEAD` exactly matches `origin/main`,
prepare the local tag with:

```bash
git fetch origin main
scripts/prepare-release-tag.sh v0.2.0
```

The command rebuilds and validates the complete candidate, creates the
human-readable annotated tag locally, re-reads its identity, and prints the
tag-object SHA and peeled source commit. It never pushes. Inspect those exact
identities before pushing only the printed tag ref. For v0.2.0, that command is:

```bash
git push origin refs/tags/v0.2.0
```

Do not push a branch, another tag, or a rewritten tag as part of that approval.
The human tag push is the release authorization boundary; GitHub Actions owns
the mechanical draft, asset, and publication transitions.

Before the tag is pushed, enable the repository's immutable Releases setting
and create two active tag rulesets covering exactly `refs/tags/v*`. The first
must restrict updates and deletions with no bypass actors. The second must
restrict creation and allow only the designated release maintainers to bypass
that creation rule. Record their numeric IDs in the
`ACS_RELEASE_TAG_RULESET_ID` and `ACS_RELEASE_TAG_CREATION_RULESET_ID`
repository variables. The creation ruleset must have exactly one `User` bypass
actor in `always` mode; record that user's numeric ID as
`ACS_RELEASE_TAG_CREATOR_ID`. The tag-triggering actor must match that ID.

Configure a `release` environment restricted to `v*` tag refs, with no
required reviewers. For a sole maintainer, a self-review prohibition would make
publication impossible and a self-approval click would not add an independent
reviewer. The environment scopes the policy credential; it is not a second
human authorization gate.

Install one repository-only policy GitHub App. It needs
Administration(write), because GitHub omits ruleset bypass actors from weaker
tokens; store its client ID as `ACS_RELEASE_POLICY_APP_CLIENT_ID` and its key as
the `ACS_RELEASE_POLICY_APP_PRIVATE_KEY` environment secret. The publication
job uses its own job-scoped `GITHUB_TOKEN` with Contents(write), while the rest
of the workflow remains read-only. The policy App token cannot publish a
Release, the workflow token cannot inspect the creation-rule bypass actor, and
no personal access token is accepted. The tagged commit must be contained in
the current protected `main` history, and the tag-triggering actor must be the
single User authorized by the creation ruleset.

The tag workflow builds once, transfers those bytes through all four
native jobs, attests the four archives and checksum manifest, and only then
creates or resumes a draft Release. It uploads only missing assets whose names
are in the exact Release Artifact Set and rejects conflicting assets or
metadata. A complete draft is made public with one final transition. A rerun
of the unchanged tag resumes a compatible draft or accepts the already
immutable, byte-identical Release; it never deletes, replaces, or rebuilds an
asset during publication.

If any gate fails, no public Release is created. Correct source, notes,
workflow configuration, tags, or artifact bytes with a new patch
version. Never move a published tag or replace a published asset.

After publishing the immutable tag, repeat the public Supported Install Path on
clean macOS 26 arm64 and Ubuntu 24.04 amd64 reference hosts. Download and
inspect `install.sh`, exercise both its default and custom destinations, and
require exact `acs v0.2.0` output. Independently verify the public archive with
`SHA256SUMS` and GitHub provenance, then repeat the Profile dry run,
authenticated Devin launch, normal exit, Session isolation, and cleanup. The
README contains the public commands; the checklist records only sanitized
results and public identifiers.

The source installation below is a compatibility check, not the Supported
Install Path. Run it in another clean temporary `GOBIN` only when the module
proxy is part of the release audit:

```bash
tagged_gobin="$(mktemp -d)"
GOBIN="$tagged_gobin" go install github.com/alcimerio/ai-config-selector/cmd/acs@v0.2.0
"$tagged_gobin/acs" version
rm "$tagged_gobin/acs"
rmdir "$tagged_gobin"
```

The tagged installation must print `acs v0.2.0`. A local checkout without
qualifying release metadata prints `acs devel`. Do not move or reuse a
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

For release documentation, reviewers must also reconcile README, contributor,
architecture, version-controlled release-note, and checklist terminology;
execute safe local equivalents of documented commands against controlled
assets; and perform independent cumulative Standards and Spec reviews against
the fixed base. Record unavailable human and production gates truthfully.

Keep the pull request title in Conventional Commit form. When squash-merging,
set the resulting commit subject to `<pull request title> (#<pull request
number>)` and verify that exact subject from the merged commit SHA.

Maintainers may ask to narrow, redesign, or split a contribution before
merging it.

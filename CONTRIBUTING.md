# Contributing

ACS v0.4.0 is a macOS-first project. Supported runtime behavior and release
evidence cover macOS 26 on arm64 and Intel. Linux/Bubblewrap source is retained,
but Linux failures are not release blockers and do not imply a support promise.

## Local setup

Install Go 1.25 or later, clone the repository, and run:

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
- Keep Profile materialization target-independent. Credentials and executable
  verification belong to the target adapter.
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

The retained Linux implementation may be compiled as a non-blocking observation:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -run '^$' ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -run '^$' ./...
```

Do not publish Linux archives, add Linux native release jobs, or describe Linux
as supported without a separate decision that restores ownership and evidence
for that platform.

## Optional authenticated Devin smoke

The credential-free native suite is the release gate. A maintainer may run the
opt-in authenticated smoke locally as supplemental confidence; follow
[docs/authenticated-release-smoke.md](docs/authenticated-release-smoke.md).
Never paste or capture account details, credential contents, target output, or
Session contents in an issue, PR, artifact, or workflow summary.

## Pull requests

Before opening a PR:

1. Run formatting, vet, normal tests, and race tests on macOS.
2. Run the native sandbox-shell test from a normal terminal.
3. Inspect `git diff --check` and the complete diff.
4. Explain the user-visible contract and the tests that prove it.
5. Confirm that no release asset, tag, or external state is changed by the PR.

The PR gates install the same candidate bytes on macOS 26 arm64 and Intel. Both
native jobs must pass before merge. The Linux compile observation is explicitly
non-blocking.

## Release preparation

Release tags are immutable and created only after the release-preparation PR is
merged to protected `main`.

For v0.4.0:

```sh
scripts/release-candidate.sh v0.4.0
scripts/prepare-release-tag.sh v0.4.0
git push origin refs/tags/v0.4.0
```

The first command requires a clean worktree and creates exactly:

```text
acs_0.4.0_darwin_arm64.tar.gz
acs_0.4.0_darwin_amd64.tar.gz
SHA256SUMS
install.sh
```

The tag workflow validates annotated tag identity and ancestry, builds the
candidate once, installs the exact bytes on both macOS targets, runs normal,
race, and black-box acceptance tests, attests the archives and checksum
manifest, and publishes through the protected `release` environment.

Never move or delete a release tag. If a candidate fails, fix the source in a
new commit and prepare a new version. Do not treat a local build or authenticated
smoke as a replacement for the two native artifact gates.

Record pre-tag and post-publication evidence in
[docs/releases/v0.4.0-checklist.md](docs/releases/v0.4.0-checklist.md).

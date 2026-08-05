# Contributing to AI Config Selector

Thanks for contributing to AI Config Selector (ACS).

## Before you start

ACS currently supports macOS and the Devin CLI. Read
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
go test -tags=integration ./internal/adapter/devin
```

This opt-in test requires macOS, an installed Devin CLI, and an authenticated
Devin account. It reads the existing authenticated state. Run it only when the
machine owner has agreed to that access. The release checklist includes this
test; `go test ./...` and the Ubuntu workflow exclude it.

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

Before tagging a release, start from the verified `origin/main` commit on a
supported macOS 26 Apple Silicon machine with Devin installed and authenticated.
Confirm the worktree and commit, then build ACS into a clean temporary `GOBIN`:

```bash
git fetch origin
git switch main
git pull --ff-only origin main
git status --short --branch

smoke_gobin="$(mktemp -d)"
GOBIN="$smoke_gobin" go install ./cmd/acs
"$smoke_gobin/acs" version
```

The local build must print `acs devel`. Create a uniquely named Profile through
the complete builder, inspect it, and launch Devin:

```bash
smoke_profile="release-smoke-$(date +%Y%m%d%H%M%S)"
"$smoke_gobin/acs" devin create-profile --name "$smoke_profile"
"$smoke_gobin/acs" devin --profile "$smoke_profile" --dry-run
"$smoke_gobin/acs" devin --profile "$smoke_profile"
```

Select at least one discovered Skill during creation. Confirm that the dry run
names the selected global Skills and that the interactive launch starts with a
usable authenticated Devin session. Exit Devin normally, verify that ACS left
no Session for the completed launch under `~/.acs/sessions/`, and remove only
the uniquely named smoke-test Profile after recording the result:

```bash
rm "$HOME/.acs/profiles/$smoke_profile.json"
rm "$smoke_gobin/acs"
rmdir "$smoke_gobin"
```

Run the opt-in real-Devin integration test and all normal repository gates on
the same verified commit. After publishing the immutable tag, repeat the
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

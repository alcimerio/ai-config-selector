# AI Config Selector

AI Config Selector (ACS) manages named capability Profiles for AI coding CLIs.
Choose a Profile when you launch a supported CLI to control which capabilities
it receives without changing its real global installation.

ACS separates shared Profile behavior from target-specific CLI adapters. The
`v0.1.0` release supports one adapter, Devin, and one Profile Component
Category, Skills.

## Supported scope

ACS `v0.1.0` supports:

- macOS 26 on Apple Silicon;
- the Devin CLI, installed and authenticated;
- user-global Skills discovered from Devin and shared-agent locations;
- interactive Profile creation, persistence, dry-run inspection, and launch;
- configuration isolation through an ephemeral Session.

Go 1.25 or later is required to install ACS from source. The Profile Builder
requires confirmation before it creates an empty Profile.

## Install

Install the supported release with an explicit module version:

```bash
go install github.com/alcimerio/ai-config-selector/cmd/acs@v0.1.0
acs version
```

A tagged installation prints:

```text
acs v0.1.0
```

Your Go binary directory must be on `PATH`. To upgrade later, rerun the install
command after replacing `v0.1.0` with the exact published tag from the GitHub
Releases page, then run `acs version` to verify the installed version.

ACS does not update itself or install an unspecified latest version.

### Build a development binary

Clone the repository and build the CLI from a local checkout:

```bash
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
./bin/acs version
```

A local checkout does not carry release module metadata, so the final command
prints `acs devel` instead of a release version. The examples below use `acs`;
substitute `./bin/acs` when running a local build.

## Current adapter: Devin

The `devin` command selects the supported CLI adapter. The adapter discovers
user-global Skills from:

```text
~/.config/devin/skills/
~/.agents/skills/
```

### Create a Profile

Create a named Profile for Devin:

```bash
acs devin create-profile --name backend-review
```

ACS opens a keyboard-driven Profile Builder. Its overview lists the supported
categories and their selection counts. Open Skills with Enter, Space, or
Right; use Space or Enter to select bundles; use `/` to search; then return to
the overview with Left or Escape and choose Create Profile. The Builder keeps
each category's state while you navigate.

Catalog discovery starts when Skills is first opened. A failed load offers
Retry and Back. Creating an empty Profile or saving after a category load
failure requires explicit confirmation. Saving and cancellation preserve the
draft across recoverable errors, and changed drafts require confirmation
before they are discarded.

Every screen shows its valid keys. If the terminal is smaller than 64 columns
by 18 rows, resize it to restore the active screen without losing the draft.
`Ctrl+C`, Escape on the overview, and Cancel share the same discard flow. ACS
stores a completed Profile under `~/.acs/profiles/` and prints cancellation
only after restoring the terminal.

Profile names contain 1 to 64 letters, numbers, dots, underscores, or hyphens
and must start with a letter or number. ACS will not overwrite an existing
Profile.

### Inspect a launch

Use a dry run to inspect the selected global Skills, their planned Session
paths, and any repository-local Skills that Devin may inherit:

```bash
acs devin --profile backend-review --dry-run
```

A dry run does not create a Session or start Devin.

### Launch Devin

Launch Devin with the Profile:

```bash
acs devin --profile backend-review
```

The adapter creates an ephemeral Session with a synthetic home, copies the
selected Skill Bundles and the existing Devin credential into that Session,
verifies the selection and authentication state, and starts Devin in the
current working directory. ACS removes the Session after Devin exits.

Repository-local Skills remain under Devin's control. ACS reports them during
a dry run but does not copy, filter, or isolate them.

## Profiles and compatibility

ACS follows semantic versioning, but releases before `v1.0.0` may change CLI
or Profile compatibility in a new minor release. Patch releases within the
same minor line are intended to remain backward compatible. Install explicit
versions and read their release notes before upgrading.

ACS `v0.1.0` writes Profile envelope version 2 and supports loading version-1
Profiles by normalizing them in memory without rewriting their files. An older
Profile that lacks a category receives that category's empty selection, so an
upgrade does not enable capabilities. ACS can add an empty category to the
version-2 envelope without bumping the envelope version. Each category owns
and evolves its independent `schemaVersion`. ACS rejects unsupported schemas
and unknown categories.

## Known limitations

- macOS 26 on Apple Silicon is the only supported platform.
- Devin is the only production CLI Adapter.
- Skills is the only production Profile Component Category.
- Profiles cannot be listed, edited, deleted, imported, or exported through
  the CLI.
- ACS does not filter repository-local Skills.
- The synthetic home provides configuration isolation, not an OS sandbox.
  It does not restrict network access or known absolute host paths.
- ACS does not manage MCP servers, hooks, instructions, agents, or arbitrary
  target settings.

Read [the architecture document](docs/architecture.md) for the domain model,
module boundaries, lifecycle, schema, and security properties.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, verification commands,
the opt-in real-Devin integration test, and release validation procedure.

## License

ACS is available under the [MIT License](LICENSE).

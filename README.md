# AI Config Selector

AI Config Selector (ACS) manages named capability Profiles for AI coding CLIs.
Choose a Profile when you launch a supported CLI to control which capabilities
it receives without changing its real global installation.

ACS separates shared Profile behavior from target-specific CLI adapters. The
current implementation includes a Devin adapter and the Skills capability
category. The adapter boundary can support additional CLIs without changing
what a Profile is.

## Project status

ACS is pre-release software. The current implementation runs on macOS, targets
Devin, and manages Skills. It does not provide packaged binaries yet.

## Requirements for the current implementation

- macOS for the current adapter
- Go 1.25 or later
- Devin installed and authenticated to use the current adapter
- one or more user-global Skills, unless you plan to create an empty Profile

## Build from source

Clone the repository and build the CLI:

```bash
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
```

The examples below use `./bin/acs`. You can also run `go install ./cmd/acs`
and use `acs` if your Go binary directory is on `PATH`.

## Current adapter: Devin

The `devin` command selects the current CLI adapter. Future adapters can expose
their own target command while using the same Profile workflow.

The Devin adapter discovers user-global Skills from:

```text
~/.config/devin/skills/
~/.agents/skills/
```

### Create a Profile

Create a named Profile for the target:

```bash
./bin/acs devin create-profile --name backend-review
```

ACS opens a keyboard-driven Profile Builder. Open Skills with Enter, Space, or
Right; use Space or Enter to select bundles; use `/` to search; then return to
the overview with Left or Escape and choose Create Profile. Every screen shows
its valid keys. If the terminal is smaller than 64 columns by 18 rows, resize
it to restore the active screen without losing the draft. `Ctrl+C`, Escape on
the overview, and Cancel share the same discard flow. ACS stores a completed
Profile under `~/.acs/profiles/` and prints cancellation only after restoring
the terminal.

Profile names contain 1 to 64 letters, numbers, dots, underscores, or hyphens
and must start with a letter or number. ACS will not overwrite an existing
Profile.

### Inspect a launch

Use a dry run to inspect the selected global Skills, their planned Session
paths, and any repository-local Skills that Devin may inherit:

```bash
./bin/acs devin --profile backend-review --dry-run
```

A dry run does not create a Session or start Devin.

### Launch the target CLI

Launch the selected target with the Profile:

```bash
./bin/acs devin --profile backend-review
```

The current adapter creates an ephemeral Session with a synthetic home, copies
the selected Skill Bundles and the existing target credential into that
Session, verifies the selection and authentication state, and starts the
target in the current working directory. ACS removes the Session after the
target exits.

Repository-local Skills remain under Devin's control. ACS reports them during
a dry run but does not copy, filter, or isolate them.

## Isolation boundary

The current adapter's synthetic home isolates normal target configuration
discovery from your global Skill directories. It does not sandbox the target
process, restrict network access, or prevent access to known absolute host
paths.

Read [the architecture document](docs/architecture.md) for the domain model,
module boundaries, lifecycle, and security properties.

ACS does not yet manage MCP servers, hooks, instructions, agents, or arbitrary
target settings.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, verification commands,
and pull request expectations.

## License

ACS is available under the [MIT License](LICENSE).

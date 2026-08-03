# AI Config Selector

AI Config Selector (ACS) launches an AI coding CLI with a named selection of
user-global capabilities. A Profile records which capabilities you want for a
session without changing the CLI's real global installation.

ACS currently supports Skills in the Devin CLI on macOS. The project is
pre-release software and does not provide packaged binaries yet.

## Requirements

- macOS
- Go 1.25 or later
- the Devin CLI installed and authenticated
- one or more user-global Skills, unless you plan to create an empty Profile

ACS discovers Devin's user-global Skills from:

```text
~/.config/devin/skills/
~/.agents/skills/
```

## Build from source

Clone the repository and build the CLI:

```bash
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
```

The examples below use `./bin/acs`. You can also run `go install ./cmd/acs`
and use `acs` if your Go binary directory is on `PATH`.

## Create a Profile

Create a named Profile for Devin:

```bash
./bin/acs devin create-profile --name backend-review
```

ACS displays the discovered global Skill Bundles and asks for a
comma-separated selection of their numbers. It stores the resulting Profile
under `~/.acs/profiles/`.

Profile names contain 1 to 64 letters, numbers, dots, underscores, or hyphens
and must start with a letter or number. ACS will not overwrite an existing
Profile.

## Inspect a launch

Use a dry run to inspect the selected global Skills, their planned Session
paths, and any repository-local Skills that Devin may inherit:

```bash
./bin/acs devin --profile backend-review --dry-run
```

A dry run does not create a Session or start Devin.

## Launch Devin

Launch Devin with the Profile:

```bash
./bin/acs devin --profile backend-review
```

ACS creates an ephemeral Session with a synthetic home, copies the selected
Skill Bundles and the existing Devin credential into that Session, verifies
the selection and authentication state, and starts Devin in the current
working directory. ACS removes the Session after Devin exits.

Repository-local Skills remain under Devin's control. ACS reports them during
a dry run but does not copy, filter, or isolate them.

## Isolation boundary

The synthetic home isolates Devin's normal configuration discovery from your
global Skill directories. It does not sandbox the Devin process, restrict
network access, or prevent access to known absolute host paths.

Read [the architecture document](docs/architecture.md) for the domain model,
module boundaries, lifecycle, and security properties.

## Project scope

The current implementation supports one target CLI and one capability
category. The Profile model and adapter boundary allow future target CLIs and
categories, but ACS does not yet manage MCP servers, hooks, instructions,
agents, or arbitrary target settings.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, verification commands,
and pull request expectations.

## License

ACS is available under the [MIT License](LICENSE).

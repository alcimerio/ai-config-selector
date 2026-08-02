# Architecture

AI Config Selector (ACS) creates named Profiles of capabilities and applies
them when it launches a supported AI coding CLI. Each CLI Adapter translates a
Profile into target-specific discovery paths, runtime configuration, preflight
checks, and launch behavior.

## Product model

A Profile belongs to one target CLI. It records the user's capability choices
through stable references and leaves target-specific discovery and runtime
rules to a CLI Adapter. Shared modules own Profile persistence, reference
resolution, Session lifecycle, and the interactive process contract.

The current vertical slice implements Skills as the first capability type and
Devin as the first CLI Adapter. The product boundary permits additional
capability types and CLI Adapters.

## Implemented scope

The current implementation supports:

- macOS;
- one CLI Adapter, for Devin;
- user-global Skills discovered from Devin and shared-agent locations;
- named Profiles stored on the local machine;
- interactive Profile creation;
- dry-run inspection;
- interactive Devin launches through an ephemeral Session.

The current Profile schema does not represent MCP servers, hooks, instructions,
agents, or arbitrary target settings. The Devin Adapter leaves
repository-local Skills under Devin's control.

## Core concepts

**Profile**: A named, machine-local selection for one target CLI. A Profile
stores Skill References rather than copies of Skills.

**Skill Reference**: The stable identity of a selected global Skill Bundle. It
combines an adapter-owned source with a bundle-relative path, such as
`devin-config:code-review`.

**Skill Bundle**: A selectable Skill directory, including its `SKILL.md` and
any relative scripts, references, or assets.

**Skill Catalog**: The global Skill Bundles ACS can discover at a point in
time. The catalog can contain the same display name from different sources.

**CLI Adapter**: The target-specific boundary that discovers capabilities,
builds a launch plan, prepares target state, verifies compatibility, and starts
the target CLI.

**Session**: An ephemeral launch environment under
`~/.acs/sessions/session-*`. It contains a synthetic home, selected Skill
Bundles, and the target state needed for the child process. The current Devin
Adapter adds an allowlisted Devin credential.

## Module boundaries

| Module | Responsibility |
| --- | --- |
| `cmd/acs` | Enforces platform support, resolves host paths, and assembles the application. |
| `internal/cli` | Parses public commands and coordinates Profile creation, dry runs, and launches through narrow interfaces. |
| `internal/profile` | Validates Profile names and owns local JSON persistence. |
| `internal/skills` | Defines Skill Catalog types and resolves strict Skill References. |
| `internal/adapter/devin` | Encapsulates Devin discovery paths, Session layout, preflight checks, launch planning, and process supervision. |
| `internal/launch` | Owns Session leases and the CLI-neutral launch plan and terminal types. |

```mermaid
flowchart LR
    User[User]

    subgraph Core[ACS shared modules]
        direction LR
        CLI[ACS CLI]
        Profiles[(Profile Store)]
        Capabilities[Capability Model<br/>Skills today]

        CLI -->|save / load| Profiles
        CLI -->|resolve references| Capabilities
    end

    subgraph AdapterBoundary[Target-specific adapter boundary]
        Adapter[CLI Adapter<br/>discover · plan · preflight · launch<br/>Devin today]
    end

    Global[Global capabilities<br/>adapter-owned discovery roots]
    Allowed[Allowlisted target state<br/>credential today]

    subgraph SessionBoundary[Synthetic home — configuration isolation only]
        Session[Ephemeral Session<br/>selected bundles + target state]
    end

    Repository[Repository-local capabilities<br/>target-native discovery]
    Target[Target AI coding CLI]

    User --> CLI
    CLI -->|discover / plan / launch| Adapter
    Adapter -->|read| Global
    Adapter -->|materialize| Session
    Allowed -->|allowlisted copy| Session
    Session -.->|HOME + XDG| Target
    Adapter -->|preflight / start| Target
    Repository -.->|inherited discovery| Target
```

The CLI layer depends on catalog, storage, planning, and launch interfaces. A
CLI Adapter implements target-specific catalog, planner, and launcher behavior.
Profile storage and Skill Reference resolution do not depend on target paths.
The Session boundary in the diagram represents configuration isolation; it is
not an OS sandbox around the target process.

## Profile lifecycle

ACS creates a Profile through this sequence:

1. validate the Profile name;
2. discover the current global Skill Catalog;
3. collect the user's selection;
4. store the selected source-and-path references in a versioned Profile.

Profiles live at `~/.acs/profiles/<name>.json`. ACS restricts the profiles
directory to the user (`0700`) and each Profile file to the user (`0600`). It
writes and syncs a temporary file in the profiles directory, then publishes it
without replacing an existing Profile name.

Before a dry run or launch, ACS loads the Profile and validates its schema
version and target. It discovers a new Skill Catalog and requires each saved
Skill Reference to match exactly one current bundle. Missing and ambiguous
references fail instead of binding to a different Skill.

## Dry-run lifecycle

A dry run resolves the Profile and asks its CLI Adapter for a launch plan. The
current Devin plan reports:

- selected global Skill Bundles and their planned Session paths;
- repository-local Skill Bundles that Devin may inherit.

A dry run does not create a Session or start Devin.

## Launch lifecycle

```mermaid
sequenceDiagram
    actor User
    participant ACS as ACS CLI
    participant Store as Profile Store
    participant Model as Capability Model
    participant Adapter as CLI Adapter
    participant Session
    participant Target as Target AI coding CLI

    User->>ACS: Launch Profile
    ACS->>Store: Load Profile
    Store-->>ACS: Saved capability references
    ACS->>Adapter: Discover current catalog
    Adapter-->>ACS: Catalog
    ACS->>Model: Resolve saved references against catalog
    Model-->>ACS: Resolved bundles or error
    ACS->>Adapter: Launch resolved Profile
    Adapter->>Session: Create lease
    Adapter->>Session: Materialize bundles and allowlisted state
    Note over Session,Target: Synthetic home changes configuration discovery
    Note over Session,Target: Repository-local capabilities remain visible
    Adapter->>Target: Run preflight with Session environment
    Target-->>Adapter: Capability and authentication status
    Adapter->>Target: Start interactive process with Session environment
    Target-->>Adapter: Exit status
    Adapter->>Session: Remove Session
    Adapter-->>ACS: Exit status
    ACS-->>User: Return exit status
```

The current Devin Adapter creates a synthetic home, copies each selected Skill
Bundle into its Devin discovery location, and copies the existing Devin
credential when present. It points `HOME` and the XDG configuration, data,
cache, and state variables at the synthetic home before preflight and launch.
The interactive process inherits the invoking terminal. ACS preserves signals,
resize events, and the child exit status.

Session leases let concurrent launches coexist. A later launch removes an
abandoned Session only when no process holds its lease.

## Implemented adapter: Devin

The adapter discovers user-global Skill Bundles from:

```text
$HOME/.config/devin/skills/
$HOME/.agents/skills/
```

It recognizes repository-local Skill Bundles under:

```text
<repository>/.devin/skills/
<repository>/.agents/skills/
```

ACS manages the global sources. Devin may inherit the repository-local sources,
so the dry run reports them separately.

The adapter copies only this existing Devin state into a Session:

```text
$HOME/.local/share/devin/credentials.toml
```

It does not copy the surrounding Devin configuration, MCP configuration, hooks,
rules, or unselected global Skills.

Before the interactive process starts, the adapter runs two probes inside the
Session environment:

1. `devin skills list --json` must report exactly the selected managed global
   Skill Bundles after built-in and repository-local Skills are excluded;
2. `devin auth status` must report a usable existing login.

Command failures, incompatible output, unmanaged global sources, catalog
mismatches, and unavailable authentication abort the launch. Preflight errors
expose capability-level diagnostics without returning subprocess output,
credentials, environment values, or account details.

## Isolation boundaries

The synthetic home isolates Devin's normal configuration discovery from the
user's global Skill directories. ACS copies only selected global Skill Bundles
and the allowlisted credential into that home.

The current runtime does not place the Devin process inside an OS filesystem
sandbox. A process that knows an absolute host path may still read it. ACS also
preserves Devin's normal network access. The Session provides configuration
isolation, not containment for hostile code.

Repository-local Skills remain visible because Devin runs in the selected
repository. ACS reports them but does not filter, copy, or manage them.

## Invariants

- ACS never modifies the user's global Skill directories when creating or
  launching a Profile.
- A Skill Reference never silently rebinds after a bundle moves or disappears.
- ACS materializes the complete selected Skill Bundle.
- Adapter preflight fails closed when ACS cannot verify the selected global
  catalog and usable authentication.
- Dry-run output distinguishes ACS-managed global Skills from inherited
  repository-local Skills.
- Interactive launch preserves the invoking terminal and the target CLI exit
  status.
- Session cleanup does not remove a Session held by a concurrent process.

## Current limitations

- ACS rejects platforms other than macOS.
- ACS ships only the Devin Adapter.
- The shared Profile schema and capability interfaces currently model Skills.
- Profiles cannot be edited, deleted, imported, or exported through the CLI.
- ACS does not filter repository-local Skills.
- ACS does not provide whole-process filesystem or network containment.

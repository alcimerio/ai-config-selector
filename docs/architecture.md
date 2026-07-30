# AI Config Selector: MVP architecture decisions

**Status:** Accepted for the first MVP  
**Scope:** Documentation only; no implementation is included in this change.

## Product hypothesis

AI Config Selector (ACS) launches an AI coding CLI with a reusable, explicit selection of capabilities instead of exposing every globally installed capability by default.

The first hypothesis to validate is deliberately narrow:

> A developer can create a named Devin profile by interactively selecting individual skills, then launch Devin later with exactly that saved global-skill selection.

ACS is a profile launcher. It is not initially a general configuration manager or a security sandbox.

## MVP scope

The first MVP supports:

- one CLI: Devin;
- one configurable component: skills;
- discovery of globally available skills;
- interactive creation of named profiles;
- reuse of a profile when launching Devin;
- materialization of each selected skill as a complete bundle;
- a synthetic configuration environment that does not modify the user's global installation;
- a dry-run view of the resolved execution plan.

The first MVP does not support:

- Codex, Claude Code, or other CLIs;
- selecting arbitrary Devin settings or config files;
- hooks, MCP servers, agents, or instructions as separate selectable components;
- the proposed `--raw` mode;
- a strong OS security boundary;
- filtering repository-local skills.

## Primary user flow

Create a profile:

```bash
acs devin create-profile --name backend-review
```

ACS discovers supported global skills and presents an interactive selector. The user selects skills individually, not an entire source directory.

Conceptually:

```text
Create profile: backend-review

Select skills:

[x] code-review
[x] postgres-review
[ ] frontend-design
[ ] pdf

2 skills selected
```

Run Devin with the saved selection:

```bash
acs devin --profile backend-review
```

Inspect what would be loaded without starting Devin:

```bash
acs devin --profile backend-review --dry-run
```

## Decision: profiles are the primary interface

The primary workflow is profile-based rather than a long list of flags on every invocation.

A profile initially records:

- the target CLI, which is always Devin in the MVP;
- the profile name;
- the identities and sources of the selected skills.

The exact on-disk serialization format and storage location are intentionally not fixed by this decision. They should be chosen during implementation without expanding the product scope.

A future direct mode may allow commands such as:

```bash
acs devin --raw --skill skill1 --skill skill2 --hook hook1
```

That syntax is reserved as a design direction, not part of the MVP contract.

## Decision: skills are selected individually

A skill source directory is used for discovery. It is not the unit the user selects.

The units are:

- **skill source:** a directory containing zero or more skills;
- **skill:** one selectable capability identified by its directory and `SKILL.md`;
- **skill bundle:** the complete selected directory, including scripts, references, and assets.

If the user selects `postgres-review`, ACS materializes the entire skill directory. Copying only `SKILL.md` would break skills that use relative resources.

The initial discovery sources are the supported global locations for Devin and the shared agent convention, including:

```text
~/.agents/skills/
~/.config/devin/skills/
```

The first implementation spike must verify Devin's current discovery behavior and paths before treating them as a stable adapter contract.

When two sources expose the same skill name, ACS must not silently choose one. The selector and dry-run output must show enough source information for the user to disambiguate them.

## Decision: CLI-specific behavior belongs in an adapter

Although only Devin is supported initially, Devin-specific knowledge should not leak throughout the ACS core.

The Devin adapter is responsible for answering questions such as:

- which global locations contain discoverable skills;
- where selected skills must appear at runtime;
- which command starts Devin;
- which environment variables or paths can redirect Devin's configuration environment;
- which authentication, settings, and state are required for a normal launch.

The core remains responsible for profile loading, selection, validation, materialization, and process supervision.

This boundary allows future adapters for Codex and Claude Code without prematurely implementing them.

## Decision: create a synthetic configuration environment

ACS must not mutate or temporarily rewrite the user's real global Devin or shared-agent directories.

At launch, ACS resolves the profile and creates an isolated configuration view containing only the selected global skills at the locations Devin expects.

Conceptually:

```text
Global skill sources
        |
        v
Discovery and catalog
        |
        v
Named profile selection
        |
        v
Devin adapter
        |
        v
Synthetic configuration environment
        |
        v
Devin process
```

Small configuration files may be copied into the temporary environment. Read-only mappings or links may be considered where appropriate, but symlinks alone must not be described as a security boundary.

## Decision: preserve the normal Devin experience where possible

The MVP focuses on filtering global skills, not forcing the user to reauthenticate or losing unrelated Devin preferences and state.

The runtime should preserve the authentication, settings, and state needed for a normal Devin session while replacing the global skill view with the profile's selection.

This is a technical risk, not a solved implementation detail. The first spike must prove that ACS can preserve the required Devin data without reintroducing every global skill through a shared parent directory.

If that separation is not possible with Devin's supported configuration mechanisms, the implementation must document the limitation before weakening the profile semantics.

## Decision: synthetic environment is not a security sandbox

The MVP provides configuration isolation: unselected global skills are not placed in Devin's normal discovery paths inside the ACS-managed environment.

It does not claim that the Devin process is unable to read arbitrary host paths. Without an OS sandbox, a process that knows an absolute path may still access it.

Strong isolation may later be implemented with platform-specific backends such as:

- Bubblewrap (`bwrap`) on Linux;
- Seatbelt/`sandbox-exec` on macOS, with its legacy status treated as a portability risk;
- a compatible external backend such as `ai-jail`.

Sandboxing remains separate from profile resolution so it can be added without redesigning profiles.

## Repository-local skills

The MVP selects and filters global skills only.

Skills already present in the working repository may still be discovered by Devin according to Devin's own project rules. ACS must not claim that a profile is the only source of all skills until repository-local discovery can also be controlled.

The dry-run output should distinguish:

- selected global skills managed by ACS;
- project-local skills that Devin may inherit and that ACS does not filter in the MVP.

A future profile policy may support `inherit`, `mask`, or `overlay` behavior for project-local components.

## Execution sequence

When running a profile, ACS should:

1. load the named profile;
2. resolve each saved skill against the current skill catalog;
3. fail clearly if a selected skill is missing or ambiguous;
4. ask the Devin adapter for an execution plan;
5. create the synthetic configuration environment;
6. materialize only the selected global skill bundles;
7. preserve the required Devin authentication, settings, and state;
8. show the plan and exit when `--dry-run` is used;
9. otherwise launch Devin interactively;
10. forward terminal signals, resize events, and the child exit code;
11. clean up temporary session data.

## MVP acceptance criteria

The MVP is successful when a user can:

1. create a named Devin profile through an interactive skill-by-skill selector;
2. see skill names and their source locations, including duplicate-name conflicts;
3. run Devin later using that profile;
4. confirm through `--dry-run` which global skills will be materialized;
5. use Devin without modifying the real global skill directories;
6. receive a clear error when a saved skill no longer exists.

## Deferred decisions

The following are intentionally deferred:

- the profile file format and storage path;
- profile editing, deletion, export, and import commands;
- direct `--skill` selection without a profile;
- exact `--raw` semantics;
- hooks, MCP servers, instructions, agents, and native CLI config selection;
- adapters for other AI CLIs;
- project-local component filtering;
- persistent versus ephemeral per-profile state;
- copying versus read-only mounting skill bundles;
- strong sandbox backends and network policies.

## Architectural guardrails

Future work should preserve these boundaries:

- profiles describe user intent;
- adapters translate that intent into CLI-specific paths and commands;
- the runtime materializes an execution environment;
- sandbox backends enforce security policy;
- process supervision preserves the interactive CLI experience.

This keeps skill selection useful on its own while leaving a clear path toward broader profiles and stronger isolation.

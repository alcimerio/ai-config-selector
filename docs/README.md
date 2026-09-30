# ACS documentation

[Project overview and install](../README.md) · [Get started](getting-started.md) ·
[Contribute](../CONTRIBUTING.md)

These guides describe **v0.5.0 and current source on macOS 26 Apple Silicon**
unless a page states otherwise. Check `acs version` before following examples.
Older installed binaries do not gain features when main-branch docs change.

## Start here

1. [Get started](getting-started.md): save a read-only Profile, inspect a
   credential-free shell, then choose Devin or Codex
2. [CLI guide](cli.md): find commands and understand what each check proves
3. [Security model](security-model.md): workspace, network, credential and trust boundaries
4. [Troubleshooting](troubleshooting.md): common symptoms and safe recovery routes

### Terms

- **Profile:** saved capability selections and target overlays, with references
  rather than embedded credentials or copies of Skill files
- **Skill:** a bundle with a `SKILL.md` entry; selections retain source and relative-path identity
- **Instruction bundle:** an explicitly selected Markdown file, separate from Skills
- **Workspace:** the current project directory captured when you launch
- **Overlay:** the fixed Devin or Codex integration on a common v3 Profile
- **Session:** private runtime state and a synthetic home for one contained process lifecycle
- **Authority:** effective access granted to the process tree, including target/runtime additions
- **Projection:** selected common material written into the target's expected Session layout

## Profiles and capabilities

| Guide | What it covers |
| --- | --- |
| [Common Profile format](common-profile-format.md) | v3 schema, legacy compatibility, workspace/path/executable/environment grants and overlays |
| [Manage Profiles](profiles.md) | Create, inspect, edit, clone, rename, delete and migrate; inspection JSON |
| [Diagnostics and effective capabilities](diagnostics.md) | `doctor`, validation, explanation JSON, semantic digest and readiness limits |
| [History](profile-history.md) | Local history, semantic diff, digest-bound restore, pin and prune |
| [Portable exchange](portable-profile-exchange.md) | Sanitized export/import and explicit local bindings |
| [MCP Profiles](mcp-profiles.md) | Reference-only local STDIO servers and shared process-tree authority |

## Targets and Sessions

- [Devin/Codex compatibility](shared-target-conformance.md): common behavior and target differences
- [Codex](codex.md): interactive launch, named Keychain identities, login/status/logout, refresh and recovery
- [Generic commands](generic-run.md): literal argv, fixed search path, descriptors and exits
- [Session operations](session-operations.md): durable inspection, lifecycle states and proof-gated recovery

For Devin's first launch or the fixed sandbox shell, start with
[Get started](getting-started.md).

## Releases and upgrades

- [Upgrade and recovery](manual-upgrade-recovery.md): installing updates, rollback,
  private data preservation and interrupted-state recovery
- [Current release notes](releases/v0.5.0.md): exact v0.5.0 capabilities; this file is
  also an input to the release tooling
- [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases): published artifacts and version history
- [Release preparation](../CONTRIBUTING.md#release-preparation): maintainer procedure and required evidence

Historical release documentation remains available at its Git tag. v0.3.3 was
the final Linux-supported release; historical Intel assets do not extend current
Apple Silicon support. A candidate, source build or passed CI job is not a
published release or evidence of real-account daily use.

## Architecture and development

- [Architecture](architecture.md): module ownership, authority, contained-process lifecycle and Profile transactions
- [Contributing](../CONTRIBUTING.md): setup, checks, PR expectations, optional authenticated smoke and release responsibilities
- [Native transport probes](native-transport-research.md): active opt-in research workflow; no destination-enforcement support claim

Fixture-specific documentation stays with the tests:
[rule-renderer corpus](../internal/executor/testdata/devin-rules-renderer/README.md),
[extension fixtures](../internal/extensionassessment/testdata/README.md), and
[synthetic credential provenance](../acceptance/testdata/devin-synthetic-credentials.provenance.md).
Fixture Skills and agent Markdown are deterministic test inputs, not setup templates.

# ACS documentation

[Project overview and install](../README.md) · [Get started](guides/getting-started.md) ·
[Contribute](../CONTRIBUTING.md)

These guides describe v0.5.1 and current source on macOS 26 Apple Silicon
unless a page states otherwise. Check `acs version` before following examples.
Older installed binaries do not gain features when main-branch docs change.

## Where to look

- `guides/`: installation, Profile management, launches and recovery
- `reference/`: command, file-format, security and target-compatibility contracts
- `development/`: architecture and contributor research
- `releases/`: reviewed, version-specific release-note sources

Use the links below to find a task or contract. Contributor setup and release
procedures are in [Contributing](../CONTRIBUTING.md).

## Start here

1. [Get started](guides/getting-started.md): save a read-only Profile, inspect a
   credential-free shell, then choose Devin or Codex
2. [CLI guide](reference/cli.md): find commands and understand what each check proves
3. [Security model](reference/security-model.md): workspace, network, credential and trust boundaries
4. [Troubleshooting](guides/troubleshooting.md): common symptoms and safe recovery routes

### Terms

| Term | Meaning |
| --- | --- |
| Profile | Saved capability selections and target overlays. Stores references, not credentials or Skill contents. |
| Skill | Bundle with a `SKILL.md` entry, identified by source and relative path. |
| Instruction bundle | Explicitly selected Markdown file, separate from Skills. |
| Workspace | Current project directory captured at launch. |
| Overlay | Fixed Devin or Codex integration on a common v3 Profile. |
| Session | Private runtime state and synthetic home for one contained process lifecycle. |
| Authority | Effective access granted to the process tree, including target and runtime additions. |
| Projection | Common material copied into the target's expected Session layout. |

## Profiles and capabilities

| Guide | What it covers |
| --- | --- |
| [Common Profile format](reference/common-profile-format.md) | v3 schema, legacy compatibility, workspace/path/executable/environment grants and overlays |
| [Manage Profiles](guides/profiles.md) | Create, inspect, edit, clone, rename, delete and migrate; inspection JSON |
| [Diagnostics and effective capabilities](guides/diagnostics.md) | `doctor`, validation, explanation JSON, semantic digest and readiness limits |
| [History](guides/profile-history.md) | Local history, semantic diff, digest-bound restore, pin and prune |
| [Portable exchange](guides/portable-profile-exchange.md) | Sanitized export/import and explicit local bindings |
| [MCP Profiles](guides/mcp-profiles.md) | Reference-only local STDIO servers and shared process-tree authority |

## Targets and Sessions

- [Devin/Codex compatibility](reference/shared-target-conformance.md): common behavior and target differences
- [Codex](guides/codex.md): interactive launch, named Keychain identities, login/status/logout, refresh and recovery
- [Generic commands](guides/generic-run.md): literal argv, fixed search path, descriptors and exits
- [Session operations](guides/session-operations.md): durable inspection, lifecycle states and proof-gated recovery

For Devin's first launch or the fixed sandbox shell, start with
[Get started](guides/getting-started.md).

## Releases and upgrades

`releases/vMAJOR.MINOR.PATCH.md` is the source of truth for a release's notes.
The tag checks require it, and the publication script uses its contents as the
GitHub Release body. Review changes here before tagging; do not maintain a
second, separately edited changelog. GitHub Releases is where users find the
published notes and downloads. A notes file on its own does not mean that a
version has shipped.

- [Upgrade and recovery](guides/manual-upgrade-recovery.md): installing updates, rollback,
  private data preservation and interrupted-state recovery
- [Current release notes](releases/v0.5.1.md): v0.5.1 security and maintenance changes
- [v0.5.0 release notes](releases/v0.5.0.md): capabilities introduced in the previous release
- [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases): published artifacts and version history
- [Release preparation](../CONTRIBUTING.md#release-preparation): maintainer procedure and required evidence

Historical release documentation remains available at its Git tag. v0.3.3 was
the final Linux-supported release; historical Intel assets do not extend current
Apple Silicon support. Confirm publication in GitHub Releases. Candidate builds
and CI checks do not establish real-account operation or sustained daily use.

## Architecture and development

- [Architecture](development/architecture.md): module ownership, authority, contained-process lifecycle and Profile transactions
- [Contributing](../CONTRIBUTING.md): setup, checks, PR expectations, optional authenticated smoke and release responsibilities
- [Native transport probes](development/native-transport-research.md): active opt-in research workflow; no destination-enforcement support claim

Fixture-specific documentation stays with the tests:
[rule-renderer corpus](../internal/executor/testdata/devin-rules-renderer/README.md),
[extension fixtures](../internal/extensionassessment/testdata/README.md), and
[synthetic credential provenance](../acceptance/testdata/devin-synthetic-credentials.provenance.md).
Fixture Skills and agent Markdown are deterministic test inputs, not setup templates.

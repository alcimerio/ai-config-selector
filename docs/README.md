# ACS documentation

[Project overview and install](../README.md) · [Get started](getting-started.md) ·
[Contribute](../CONTRIBUTING.md)

ACS creates named capability Profiles and runs selected targets inside a required
native sandbox. Current user guides describe **v0.5.0 and current source on macOS
26 Apple Silicon** unless a document explicitly gives another version or research
status. Check `acs version` before following command examples. Older published
binaries do not gain features because the main-branch documentation changes.

## Start here

1. [Get started](getting-started.md): install, save a read-only Profile, inspect a
   credential-free shell, then choose Devin or Codex
2. [CLI guide](cli.md): find commands and understand the different passive checks
3. [Security model](security-model.md): workspace, network, credential, and trust boundaries
4. [Troubleshooting](troubleshooting.md): common symptoms and safe recovery routes

### Terms used throughout

- **Profile:** saved capability selections and target overlays, with references
  rather than embedded credentials or copies of local Skill files
- **Skill:** a bundle with a `SKILL.md` entry; selections retain source and relative-path identity
- **Instruction bundle:** an explicitly selected Markdown file, separate from Skills
- **Workspace:** the current project directory captured when you launch
- **Overlay:** a fixed target integration, such as Devin or Codex, on a common v3 Profile
- **Session:** private runtime state and a synthetic home for one contained process lifecycle
- **Authority:** the effective access granted to that process tree, including target/runtime additions
- **Projection:** selected common material written into the target's expected Session layout

## User guides and reference

### Profiles and common capabilities

| Document | Use it for |
| --- | --- |
| [Common Profile format](common-profile-format.md) | v3 schema, legacy migration, workspace/path/executable/environment authority, target overlays |
| [Declarative creation](profile-creation.md) | Strict local JSON input, previews, no-overwrite publication |
| [Profile inspection](profile-inspection.md) | `list` / `show`, stored selections, format-1 JSON and error statuses |
| [Passive diagnostics](passive-diagnostics.md) | `doctor`, `profile validate`, exact check IDs and limits |
| [Effective capability explanation](effective-capability-explanation.md) | Requested vs added vs effective facts, semantic digest, explicit readiness probe |
| [Profile mutations](profile-mutations.md) | Edit, clone, rename, delete, migrate, cancellation and uncertain outcomes |
| [Profile history](profile-history.md) | Local history, semantic diff, digest-bound restore, pin and prune |
| [Portable exchange](portable-profile-exchange.md) | Sanitized export/import intent, required local bindings, what is not shared |
| [Instruction bundles](instruction-bundles.md) | Common Markdown selection and Devin-only rule activation |
| [MCP Profiles](mcp-profiles.md) | Reference-only local STDIO servers and shared process-tree authority |

### Targets and Sessions

| Document | Use it for |
| --- | --- |
| [Shared target conformance](shared-target-conformance.md) | Devin/Codex common behavior, target differences, daily-use acceptance checklist |
| [Interactive Codex](interactive-codex.md) | Supported pinned CLI, fixed launch recipe and auth-reference selection |
| [Codex authentication](codex-auth.md) | ACS-owned named Keychain identities, login/status/logout, refresh and recovery |
| [Generic commands](generic-run.md) | Literal argv, fixed search path, dry-run, descriptors and exits |
| [Session operations](session-operations.md) | Durable list/inspect/recover, lifecycle states and cleanup proof |

For Devin's first launch and the fixed sandbox shell, use
[Get started](getting-started.md). These flows deliberately share the common
capability reference rather than duplicating a second schema.

## Architecture and contribution

- [Architecture](architecture.md): source ownership and end-to-end data flow
- [Contained-process executor](contained-process-executor.md): lifecycle and typed resource boundaries
- [Profile repository transactions](profile-repository-transactions.md): persistence, revisions, commit outcomes and recovery evidence
- [Contributing](../CONTRIBUTING.md): local setup, portable vs native checks, PR expectations and release responsibilities
- [Open-source review, 2026-09-30](reviews/2026-09-30-open-source-review.md): complete documentation inventory, actionable follow-ups and validation limits

## Releases and upgrades

- [Manual upgrade and recovery](manual-upgrade-recovery.md): published-release installation, rollback and private data preservation; historical examples are labeled
- [Candidate migration guide](release-migration-guide.md): operator-identified development candidate, explicit source/artifact identity and separate data compatibility
- [Current-candidate handoff](current-candidate-handoff.md): the pinned v0.5.0 handoff/evidence boundary, not a floating promise about later source
- [Release readiness](release-readiness.md): v0.5.0 publication evidence and outstanding real daily-use observation
- [Authenticated Devin smoke](authenticated-release-smoke.md) and [authenticated Codex smoke](authenticated-codex-auth-smoke.md): opt-in private, real-account observations; not CI or substitutes for credential-free gates

### Versioned release and candidate records

Release notes describe a version-specific artifact or candidate, not current source.
The v0.3.0–v0.3.2 records are unpublished candidates, not public Releases. Checklists record
what was observed; unchecked historical rows must not be retroactively treated
as passing evidence. Keep the version-pinned links when citing a release.

| Version | Notes | Evidence/checklist |
| --- | --- | --- |
| v0.5.0 | [Notes](releases/v0.5.0.md) | [Publication record](releases/v0.5.0-checklist.md) |
| v0.4.0 | [Historical notes](releases/v0.4.0.md) | [Historical checklist](releases/v0.4.0-checklist.md) |
| v0.3.3 | [Historical notes](releases/v0.3.3.md) | [Historical checklist](releases/v0.3.3-checklist.md) |
| v0.3.2 | [Historical notes](releases/v0.3.2.md) | [Historical checklist](releases/v0.3.2-checklist.md) |
| v0.3.1 | [Historical notes](releases/v0.3.1.md) | [Historical checklist](releases/v0.3.1-checklist.md) |
| v0.3.0 | [Historical notes](releases/v0.3.0.md) | [Historical checklist](releases/v0.3.0-checklist.md) |
| v0.2.0 | [Historical notes](releases/v0.2.0.md) | [Historical checklist](releases/v0.2.0-checklist.md) |

v0.3.3 is the final Linux-supported release. Historical Intel assets do not
extend the current Apple Silicon support policy.

## Research, not shipped capabilities

- [Extensions assessment](extension-assessment.md): pinned plugin/hook/custom-agent findings and test-only harness evidence; no production Profile activation
- [Outbound network investigation](outbound-network-enforcement.md): feasibility/decision record; no destination allowlisting or egress-firewall claim
- [Native environment transport research](native-transport-research.md): bounded native network/descriptor probe, not destination-enforcement support

These documents retain source/version boundaries and negative evidence. Read
their status before interpreting a proposal or fixture as a supported feature.

## Test fixture documentation

These are for contributors inspecting tests, not installation or agent behavior
templates to copy into a user's setup:

- [Devin rule-renderer fixture](../internal/executor/testdata/devin-rules-renderer/README.md)
- [Extension-assessment fixtures](../internal/extensionassessment/testdata/README.md)
- [Synthetic credential provenance](../acceptance/testdata/devin-synthetic-credentials.provenance.md)
- Skill/agent Markdown under `internal/*/testdata/` supplies synthetic content
  to those tests; it is not ACS configuration guidance

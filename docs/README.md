# ACS documentation

[Install](../README.md#install) · [Get started](guides/getting-started.md) · [Contribute](../CONTRIBUTING.md)

These pages follow this checkout. Check `acs version` and use your release's Git
tag for installed behavior; main can describe changes that have not shipped.
The supported runtime is macOS 26 Apple Silicon.

## Start here

- [Get started](guides/getting-started.md): create a read-only Profile and inspect a credential-free shell
- [CLI reference](reference/cli.md): choose a command, find grammar and understand each check
- [Security model](reference/security-model.md): filesystem, network, credentials and trust boundaries
- [Troubleshooting](guides/troubleshooting.md): symptoms and recovery routes

## Manage Profiles

| Task | Page |
| --- | --- |
| Create, inspect, edit, clone, rename, delete or migrate | [Profiles](guides/profiles.md) |
| Start from a ready-made Profile file | [Example Profiles](../examples/README.md) |
| Check launch prerequisites or explain effective authority | [Diagnostics](guides/diagnostics.md) |
| Understand schemas, grants and overlays | [Common Profile format](reference/common-profile-format.md) |
| Restore, compare, pin or prune local revisions | [Profile history](guides/profile-history.md) |
| Share sanitized intent and bind local resources | [Portable exchange](guides/portable-profile-exchange.md) |
| Select local STDIO servers | [MCP Profiles](guides/mcp-profiles.md) |

## Launch and recover

- [Target compatibility](reference/target-compatibility.md): exact reviewed versions and native target locks.
- [Target conformance](reference/shared-target-conformance.md): Devin/Codex projections and compatibility
- [Codex](guides/codex.md): interactive launch, named Keychain identities, refresh and quarantine
- [Generic commands](guides/generic-run.md): literal argv, search paths, descriptors and exits
- [Session operations](guides/session-operations.md): passive inspection and proof-gated recovery
- [Upgrade and recovery](guides/manual-upgrade-recovery.md): verify replacement bytes, retain the working binary and recover stored data

Devin and the fixed sandbox shell start in [Get started](guides/getting-started.md).

## Develop and release

- [Contributing](../CONTRIBUTING.md): local setup, development rules and PR checks
- [Architecture](development/architecture.md): module ownership, process lifecycle and Profile transactions
- [Testing](development/testing.md): native/portable checks, dependency scanning, authenticated smoke and research harnesses
- [Releasing](development/releasing.md): tag preparation, immutable publication and candidate verification
- [Native transport research](development/native-transport-research.md): opt-in probes and evidence limits
- [Linux support design](design/linux-support.md): proposed security contract and staged implementation; Linux execution remains unsupported
- [Linux filesystem compiler](design/linux-filesystem-plan.md): pure mount/Landlock planning, rejection gates and remaining native proof
- [Sealed Linux launcher](design/linux-sealed-launcher.md): test-only Bubblewrap, Landlock and seccomp boundary; production Linux remains disabled
- [Linux Session containment](design/linux-session-containment.md): delegated cgroups, pidfds, gated supervision and remaining native qualification
- [Linux cleanup and recovery](design/linux-cleanup-recovery.md): authenticated settlement, retained leases, quarantine and terminal restoration

[Release-note sources](releases/) are reviewed version-specific records consumed
by publication. Use [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases)
for published history and [the latest release](https://github.com/alcimerio/ai-config-selector/releases/latest)
for downloads. A notes file alone does not mean a release shipped.

Fixture explanations stay beside their tests:
[rule-renderer receipts](../internal/executor/testdata/devin-rules-renderer/README.md),
[extension fixtures](../internal/extensionassessment/testdata/README.md) and
[synthetic credential provenance](../acceptance/testdata/devin-synthetic-credentials.provenance.md).
Fixture Skills and agent Markdown are deterministic test inputs, not setup templates.

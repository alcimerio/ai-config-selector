# CLI reference

[Documentation index](../README.md) · [Get started](../guides/getting-started.md)

This guide follows the current source. For the grammar of your installed
binary, run `acs help`, `acs COMMAND --help`, or
`acs help COMMAND`. Help is passive and works without a terminal, client,
credential, Profile directory, or Session.

## Grammar

Write the command path first, then its flags. Values are separate, nonempty
arguments; flags occur at most once. `--flag=value` is not accepted. Quote values
that contain spaces. Commands that take a positional operand, such as
`profile show NAME`, document it in their help.

```sh
acs profile show first-review --json
acs profile show --json first-review
acs devin --dry-run --profile first-review
acs codex auth login --device-auth --name work
```

`acs run` and `acs explain run` require `--` before the literal child command.
A later `--` belongs to that child. Other target commands do not accept generic
argument pass-through, backend selection, or a sandbox bypass.

```sh
acs run --profile first-review -- /usr/bin/git diff -- "path with spaces"
acs explain run --profile first-review --json -- /usr/bin/git status
```

`acs update vMAJOR.MINOR.PATCH` selects that published stable version.
`acs help COMMAND` takes the command path, not an invocation's flags. Successful
help returns exit 0 on stdout. Most command syntax errors return exit 1 on
stderr, including malformed flags alongside `--help`. Profile
history/diff/restore use a separate grammar and status contract (syntax errors
return 2); consult their contextual help and
[history reference](../guides/profile-history.md).

## Find the right command

| Task | Starting command | Detailed contract |
| --- | --- | --- |
| Recover Profile transactions | `acs profile recover [--json]` | [Profiles](../guides/profiles.md#uncertain-outcomes-and-recovery) |
| Create interactively | `acs devin create-profile --name NAME` or `acs codex create-profile --name NAME [--auth REF]` | [Get started](../guides/getting-started.md) |
| Create from local JSON | `acs profile create --file FILE --dry-run` | [Declarative creation](../guides/profiles.md#declarative-creation) |
| List / inspect | `acs profile list`, `acs profile show NAME --json` | [Inspection](../guides/profiles.md#inspection) |
| Check host / sources | `acs doctor`, `acs profile validate NAME` | [Passive diagnostics](../guides/diagnostics.md#passive-diagnostics) |
| Explain permissions | `acs explain sandbox --profile NAME` | [Effective capability explanation](../guides/diagnostics.md#effective-capability-explanation) |
| Change a Profile | `acs profile edit NAME`, then consult the operation-specific help | [Profile mutations](../guides/profiles.md#mutations) |
| Transfer sanitized intent | `acs profile export NAME`, `acs profile import validate --file FILE` | [Portable exchange](../guides/portable-profile-exchange.md) |
| Inspect / restore history | `acs profile history NAME`, `acs profile restore NAME --revision EVENT --dry-run` | [Profile history](../guides/profile-history.md) |
| Run Devin | `acs devin --profile NAME` | [Target conformance](shared-target-conformance.md) |
| Run Codex | `acs codex --profile NAME [--auth REF]` | [Interactive Codex](../guides/codex.md#interactive-launch) |
| Manage named login | `acs codex auth login --name REF` | [Codex authentication](../guides/codex.md#named-authentication) |
| Inspect or select credential provider | `acs codex auth provider [--select file\|secret-service\|keychain]` | Explicit durable choice; Linux providers and launches remain unavailable |
| Open a sandbox shell | `acs sandbox --profile NAME` | [Get started](../guides/getting-started.md) |
| Run literal argv | `acs run --profile NAME -- COMMAND [ARG...]` | [Generic run](../guides/generic-run.md) |
| Inspect / recover a Session | `acs session list`, `acs session inspect ID`, `acs session recover ID` | [Session operations](../guides/session-operations.md) |
| Check / update ACS | `acs version`, `acs update --check` | [Upgrade and recovery](../guides/manual-upgrade-recovery.md) |

Use `--help` before copying a mutation or recovery command. Remove `--dry-run`
only when you intend that command's documented change. Declarative creation and
import save without interactive confirmation. Deletion, restore and pruning have
their own confirmation requirements.

`acs codex auth provider` reports the selected provider. On Linux,
`--select file` explicitly opts into future plaintext-at-rest credential storage;
`--select secret-service` selects the future desktop keyring provider. Neither
Linux provider is available yet, and this command does not enable Linux launches.
The choice is stored in `$XDG_CONFIG_HOME/acs/credential-provider.json`, defaulting
to `~/.config/acs/credential-provider.json`. The ACS directory must be 0700 and
the file 0600; unsafe ownership, symlinks, relative XDG paths and malformed records
are rejected. Repeating a choice succeeds; switching providers is refused.
macOS continues to use Keychain, independently of Linux configuration.

## What each check proves

| Check | What it does | What it does not establish |
| --- | --- | --- |
| `profile list` / `show` | Reads saved structure and sanitized selections | Source availability, credentials, target readiness |
| `profile validate` | Checks supported stored structure and selected Skill-source resolution | Full instruction/path/env/MCP/runtime readiness |
| `doctor` | Checks passive host/backend-file prerequisites; optional target availability | Target versions, authentication, actual containment |
| `explain` | Reports requested/added/effective/unsupported authority | Local content identity or readiness from a semantic digest alone |
| `explain --check-native-readiness` | Adds the explicit bounded native readiness check | An end-to-end target launch |
| `sandbox`, `devin`, or `run --dry-run` | Plans supported launch inputs and bounded backend readiness; no Session | Successful target execution or hosted-account behavior |
| `codex --dry-run` | Validates stored Profile/reference syntax and explains the plan | Skill discovery, Keychain access, target probing, authentication readiness |
| `profile create` / `import --dry-run` | Validates and previews the proposed stored representation | Available Skill material, credentials, or a successful launch |
| `update --check` | Reads stable release metadata | Install success; it does not download an archive or change user data |

JSON formats are command-specific and independently versioned. Do not assume a
`profile show` response has the same schema as `doctor`, `explain`, or exchange
JSON. Local Profile JSON is not a portable export.

## Exit and failure behavior

Syntax and ACS failures generally return 1 with sanitized diagnostics.
Profile inspection/validation can report per-entry structural failures; consult
their JSON contracts for exact statuses. Ordinary target exits preserve the
target's exit code. Interrupted interactive creation returns 130; contained
commands report cancellation only after required cleanup is proven.

A failed or interrupted mutation does not always mean nothing was written. Check
whether the result is committed, not committed, or unknown, and whether recovery
is required, before retrying. Follow
[transaction recovery](../development/architecture.md#profile-repository-transactions)
and [Session recovery](../guides/session-operations.md), not manual deletion of
internal state.

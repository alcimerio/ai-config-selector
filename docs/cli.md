# CLI guide

[Documentation index](README.md) · [Get started](getting-started.md)

This is a navigation guide for v0.5.0/current source. The exact command grammar
ships with your binary: run `acs help`, `acs COMMAND --help`, or
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

`acs update vMAJOR.MINOR.PATCH` is an explicit version operand, not an arbitrary
argument. `acs help COMMAND` takes the command path, not an invocation's flags.
Successful help returns exit 0 on stdout. Most command syntax errors return
exit 1 on stderr, including malformed flags alongside `--help`. Profile
history/diff/restore use a separate grammar and status contract (syntax errors
return 2); consult their contextual help and [history reference](profile-history.md).

## Find the right command

| Task | Starting command | Detailed contract |
| --- | --- | --- |
| Create interactively | `acs devin create-profile --name NAME` or `acs codex create-profile --name NAME [--auth REF]` | [Get started](getting-started.md) |
| Create from local JSON | `acs profile create --file FILE --dry-run` | [Declarative creation](profiles.md#declarative-creation) |
| List / inspect | `acs profile list`, `acs profile show NAME --json` | [Inspection](profiles.md#inspection) |
| Check host / sources | `acs doctor`, `acs profile validate NAME` | [Passive diagnostics](diagnostics.md#passive-diagnostics) |
| Explain permissions | `acs explain sandbox --profile NAME` | [Effective capability explanation](diagnostics.md#effective-capability-explanation) |
| Edit / clone / rename / delete / migrate | `acs profile edit NAME` | [Profile mutations](profiles.md#mutations) |
| Transfer sanitized intent | `acs profile export NAME`, `acs profile import validate --file FILE` | [Portable exchange](portable-profile-exchange.md) |
| Inspect / restore history | `acs profile history NAME`, `acs profile restore NAME --revision EVENT --dry-run` | [Profile history](profile-history.md) |
| Run Devin | `acs devin --profile NAME` | [Target conformance](shared-target-conformance.md) |
| Run Codex | `acs codex --profile NAME [--auth REF]` | [Interactive Codex](codex.md#interactive-launch) |
| Manage named login | `acs codex auth login --name REF` | [Codex authentication](codex.md#named-authentication) |
| Inspect a shell | `acs sandbox --profile NAME` | [Get started](getting-started.md) |
| Run literal argv | `acs run --profile NAME -- COMMAND [ARG...]` | [Generic run](generic-run.md) |
| Inspect / recover a Session | `acs session list`, `acs session inspect ID`, `acs session recover ID` | [Session operations](session-operations.md) |
| Check / update ACS | `acs version`, `acs update --check` | [Upgrade and recovery](manual-upgrade-recovery.md) |

Use `--help` before copying a mutation or recovery command. Remove `--dry-run`
only when you intend that command's documented change. Not every mutation is
interactive: declarative creation and import publish when explicitly invoked,
while deletion/restore/prune have their own confirmation contracts.

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

A failed or interrupted mutation does not always mean nothing was written.
Distinguish **committed**, **not committed**, and **unknown / recovery required**
outcomes before retrying. Follow [transaction recovery](architecture.md#profile-repository-transactions)
and [Session recovery](session-operations.md), not manual deletion of internal state.

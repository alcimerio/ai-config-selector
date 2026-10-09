# Example Profiles

[Documentation index](../docs/README.md) · [Profiles](../docs/guides/profiles.md) · [Security model](../docs/reference/security-model.md)

Each file in [profiles/](profiles/) is a complete version-3 Profile for
[declarative creation](../docs/guides/profiles.md#declarative-creation). The
files are in canonical form, contain no machine-specific paths, credentials or
named logins, and are checked in CI with the same codec as
`acs profile create --file`.

| Example | Demonstrates | Targets |
| --- | --- | --- |
| [review-readonly](profiles/review-readonly.json) | Default read-only workspace; nothing else selected | Devin, Codex, sandbox |
| [dev-secrets-excluded](profiles/dev-secrets-excluded.json) | Writable workspace with `.env`, `.env.local` and `secrets/` denied | Devin, Codex, sandbox |
| [dev-scoped-token](profiles/dev-scoped-token.json) | One secret passed by reference and renamed; one optional non-secret | Devin, Codex, sandbox |
| [docs-writer](profiles/docs-writer.json) | Read-only workspace with only `docs/` writable, plus a selected instruction file | Devin, Codex, sandbox |
| [skill-review-isolated](profiles/skill-review-isolated.json) | One selected global Skill; repository `.agents/skills` and `.devin/skills` denied | Devin, Codex, sandbox |
| [sandbox-tools-only](profiles/sandbox-tools-only.json) | No target overlay; `git` visibility for `acs sandbox` and `acs run` | sandbox, run |

## Use an example

From a checkout of this repository, preview and create the Profile, then
inspect it from the project you want to work in:

```sh
acs profile create --file examples/profiles/review-readonly.json --dry-run
acs profile create --file examples/profiles/review-readonly.json
acs profile validate review-readonly
acs explain sandbox --profile review-readonly
acs sandbox --profile review-readonly
```

Creation never overwrites an existing Profile. To use another name, copy the
file and change `name`. Launch a target with:

```sh
acs devin --profile review-readonly
acs codex --profile review-readonly --auth REF
acs run --profile sandbox-tools-only -- /usr/bin/git status
```

Codex overlays carry no `authRef`; pass your ACS-owned login with `--auth`.
See [interactive Codex](../docs/guides/codex.md#interactive-launch).

## Prerequisites and limits

- **dev-scoped-token** requires `ACS_EXAMPLE_GH_TOKEN` in the launching
  environment and fails before Session creation without it.
  `ACS_EXAMPLE_BUILD_MODE` is optional. The Profile stores only these names;
  the target and its descendants, including MCP servers, can read the value.
- **docs-writer** requires an existing `docs/` directory in the workspace and
  `~/.acs/instructions/docs-style.md`.
- **skill-review-isolated** requires a Skill bundle at
  `~/.agents/skills/code-review` with a `SKILL.md`. Do not launch it with your
  home directory as the workspace: the excluded `.agents/skills` would then
  contain the selected Skill and the launch fails closed.
- Exclusions are pathname based. They do not hide Git history, copies or names
  in parent listings; see [filesystem exclusions](../docs/reference/common-profile-format.md#filesystem-exclusions).
- ACS is not an egress firewall: a target can transmit data it can read.

To share your own variant without local paths, use
[portable exchange](../docs/guides/portable-profile-exchange.md).

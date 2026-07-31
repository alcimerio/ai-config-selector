# Verify Devin compatibility and skill isolation

ACS must verify adapter capabilities against the installed CLI instead of maintaining version allowlists. Its CI suite proves the adapter contract, and each launch runs a focused preflight that verifies the prepared ACS Session exposes exactly the selected global Skill Bundles while preserving a usable existing login. If either condition cannot be verified, ACS fails clearly rather than launching with weakened profile semantics.

## Verified Devin rules

The macOS adapter contract was established against the installed real Devin CLI. Compatibility still depends on the capability checks below, not on that CLI's version number.

Devin resolves these two user-global skill sources from the process home:

- `$HOME/.config/devin/skills/<skill-name>/SKILL.md`
- `$HOME/.agents/skills/<skill-name>/SKILL.md`

An ACS Session sets `HOME` and the matching XDG configuration, data, cache, and state roots to directories inside the Session. It materializes selected Skill Bundles only under those two global roots. The Devin Adapter does not use `--config` for isolation because that option changes the user configuration file but does not relocate both reported global skill roots.

Devin also discovers these repository-local sources from its current working directory:

- `.devin/skills/<skill-name>/SKILL.md`
- `.agents/skills/<skill-name>/SKILL.md`

Those project-local skills are not ACS-managed global skills. Adapter Preflight excludes their observed bundle paths from the managed global Skill Catalog; ACS does not copy, mask, or claim to isolate them. Devin's built-in skills are excluded for the same reason: they are not user-global Skill Bundles.

## Authentication allowlist

The only existing Devin state copied into a Session by this adapter slice is:

- `$HOME/.local/share/devin/credentials.toml`

It is copied as a user-only file. ACS does not copy the surrounding data tree, `~/.config/devin`, settings, hooks, MCP configuration, rules, or global skills. The Session copy is what Devin reads after home relocation.

## Adapter Preflight protocol

Before launch, the adapter executes both probes inside the prepared Session:

1. `devin skills list --json`; every observed non-built-in, non-project-local Skill Bundle must map to one of the two Session global roots, and the resulting source-plus-relative-path identities must exactly equal the selected fixture.
2. `devin auth status`; Devin must report a usable existing login from the allowlisted Session credential.

Command failures, invalid output, catalog mismatches, newly observed unmanaged sources, and unusable authentication all fail preflight. Diagnostics may report sanitized expected and observed skill identities and the failed capability, but never raw subprocess output, credential contents, environment values, or account details.

The release-gating macOS contract is run with `go test -tags=integration ./internal/adapter/devin`. It intentionally fails, rather than skips, when the real `devin` executable, the selected-catalog isolation behavior, or a usable existing login is unavailable.

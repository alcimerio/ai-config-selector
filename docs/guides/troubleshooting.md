# Troubleshooting

[Documentation index](../README.md) · [CLI guide](../reference/cli.md) · [Recovery guide](manual-upgrade-recovery.md)

Start with `command -v acs` and `acs version`. These identify the binary you are
actually invoking; a newer checkout does not upgrade an old installed binary.
Use `acs COMMAND --help` for that binary's grammar.

| Symptom | Check | Safe next step |
| --- | --- | --- |
| `acs: command not found` | `"$HOME/.local/bin/acs" version` for the default installer | Add the intended directory to the current terminal's `PATH`; the installer does not edit startup files |
| A documented command is unknown | `acs version`; v0.4.0 lacks the newer Profile, auth and update commands | Follow the [v0.5.0 installation/upgrade](manual-upgrade-recovery.md) instructions and verify command resolution |
| `unsupported_platform` / backend unavailable | macOS 26, Apple Silicon, system `/usr/bin/sandbox-exec`; `acs doctor` | Use a supported host; do not bypass containment or weaken security settings |
| Native tests fail only inside another sandbox | Run context and [Contributing](../../CONTRIBUTING.md) | Run native tests from a normal supported macOS terminal; report which environment failed |
| Skill missing from builder | Immediate child bundle under `~/.agents/skills` or `~/.config/devin/skills`, regular `SKILL.md` | Check source layout, clear the search, restart builder after adding material |
| A saved Skill no longer resolves | `acs profile show NAME --json`, then `acs profile validate NAME` | Restore the exact source identity or deliberately remove/reselect it in `profile edit`; display names do not rebind references |
| Workspace writes denied | `acs explain TARGET --profile NAME`; new v3 Profiles default read-only | If coding write is intended, explicitly select it in `profile edit`; don't weaken the sandbox |
| Tool not found / script cannot run | Generic commands use fixed `/usr/local/bin:/usr/bin:/bin`, not host `PATH` | Use an explicit executable path; select needed non-intrinsic interpreter/runtime visibility rather than assuming shebang inference |
| Codex version rejected | `codex --version`; supported integration is `codex-cli 0.149.1` | Use the supported target version; a newer target is not automatically compatible |
| Codex Profile has no supported overlay or auth reference | `acs profile show NAME --json`; `acs codex --help` | Use `codex create-profile`, an explicit supported overlay, and one ACS-owned named identity |
| Host `codex login` worked but ACS has no identity | `acs codex auth list` | ACS intentionally uses separate named identities; follow [ACS login](codex.md#named-authentication), not global-credential import |
| Keychain unavailable / identity quarantined | Stable error category and `acs codex auth --help` | Follow [named-auth recovery](codex.md#named-authentication); do not delete or replace credentials manually |
| Installer refuses existing `acs` | Existing direct file at destination | Stage in a new empty user-owned directory; follow the [manual upgrade guide](manual-upgrade-recovery.md) |
| `acs update` refuses layout / development binary | `command -v acs`, `acs version`, direct-file vs symlink/package-manager layout | Use the supported release installer; the updater does not adopt arbitrary layouts |
| Session remains after interruption | `acs session list`, then `acs session inspect ID --json` | Follow `acs session recover ID` and [proof-gated recovery](session-operations.md); no force-delete |
| Profile write reports unknown / recovery required | Exact outcome and printed guidance | Preserve evidence, run the supported recovery entry point, cancel the builder if it opens, then inspect before retrying |

## Dry-run passed, but launch failed

A preview is not an end-to-end launch. Codex dry-run does not probe Codex or the
Keychain. Other launch dry-runs perform bounded readiness checks but do not run
the requested target. Selected files, credentials, and host state can change
between commands. See [what each check proves](../reference/cli.md#what-each-check-proves).

## What to include in an issue

Provide a minimal synthetic reproduction, ACS version/commit, supported host
version/architecture, command shape, expected result, stable error category,
and which checks passed, failed, or were not run. Inspect every attachment first.
See [safe bug reporting](../reference/security-model.md#sharing-a-safe-bug-report) for private
information to omit and the current private-disclosure limitation.

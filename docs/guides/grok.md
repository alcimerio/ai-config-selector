# Grok Build

[Documentation index](../README.md) · [Target compatibility](../reference/target-compatibility.md) · [CLI reference](../reference/cli.md)

ACS runs the reviewed Grok Build CLI (`grok` 1.0.62) inside the required sandbox.
Install Grok separately. ACS does not download it during a launch and does not
start `grok login` inside a Session.

```sh
acs grok create-profile --name NAME
acs explain grok --profile NAME
acs grok --profile NAME --dry-run
acs grok --profile NAME
acs doctor --target grok
acs check --profile NAME --target grok
```

One Profile can include Devin, Codex, and Grok overlays. The common selections
are shared. `acs grok` requires the `grok` overlay.

## Authentication

Before the interactive process starts, ACS copies `~/.grok/auth.json` into the
Session when that file is a regular file. It does not copy `mcp_credentials.json`,
trusted folders, plugins, sessions, or the host `config.toml`.

A Profile may instead select `XAI_API_KEY` as a secret environment entry. The
host value is not inherited unless that entry is selected. If neither the
allowlisted file nor `XAI_API_KEY` is available, launch fails before Grok starts.
Sign in on the host with `grok login` (use `grok login --device-code` on a
machine without a browser), then launch ACS.

The version probe runs first and does not receive the credential or selected
environment.

## What the Session config forces

ACS writes `~/.grok/config.toml` in the Session and write-protects it, along with
an empty `trusted_folders.toml`:

- automatic updates off
- Grok's own sandbox off, so ACS containment is the only sandbox
- Cursor, Claude, and Codex compatibility scanners off, including sessions
- plugin enablement empty
- selected stdio MCP servers projected through the ACS launcher
- selected tool names listed in `disabled_mcp_tools`

Selected Skills are copied to `~/.grok/skills/<source>/<relativePath>`. Selected
instruction files are copied to `~/.grok/rules/` and loaded as global rules.

## Project files and trust

Grok can read the workspace ACS grants. Repository `.grok/skills`, `AGENTS.md`,
`.grok/rules`, project MCP, hooks, and plugins stay out of the trusted project
scope unless you accept Grok's interactive folder-trust prompt. ACS never passes
a trust flag and does not copy `~/.grok/trusted_folders.toml`.

Accepting that prompt enables those repository files inside the ACS sandbox. It
does not leave the sandbox. Declining quits Grok. A project MCP server with the
same name as a selected server can cause Grok to drop the selected server while
the directory is untrusted.

Grok's built-in web tools use ACS's coarse outbound network. Tool filtering is
a Grok feature, not a separate ACS boundary.

Grok is not a qualified Linux target. A `linux/amd64` Grok launch is refused.
Dry-run, explain, doctor, and check still report the plan and passive facts.

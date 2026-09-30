# Get started with ACS

[Documentation index](README.md) · [CLI guide](cli.md) · [Security model](security-model.md)

This guide is for v0.5.0 and current source on **macOS 26, Apple Silicon**.
Start with a credential-free shell so you can see the boundary before adding
an AI target or account. Allow about ten minutes; native setup or target login
can take longer. This is a walkthrough, not a recorded daily-use test.

## 1. Install and check the host

Follow the [release installation](../README.md#install) or
[source build](../README.md#build-from-source) instructions. In the same terminal:

```sh
command -v acs
acs version
acs doctor --target sandbox
```

`command -v` should identify the executable you deliberately installed. Release
builds print a version; source builds print `acs devel`. `doctor` checks passive
prerequisites, including the system `/usr/bin/sandbox-exec` and shell availability.
It does not execute a containment test. On an unsupported host, stop here;
there is no bypass or unsandboxed fallback.

## 2. Add an optional first Skill

A **Skill** is a local bundle with a `SKILL.md` entry file. ACS discovers immediate
child directories under `~/.agents/skills` and `~/.config/devin/skills`. It does
not install or download Skills for you. A loose `SKILL.md` at either root is not
a catalog entry.

To create a small example without overwriting an existing bundle:

```sh
mkdir -p "$HOME/.agents/skills"
mkdir "$HOME/.agents/skills/acs-first-review" && cat > "$HOME/.agents/skills/acs-first-review/SKILL.md" <<'SKILL'
---
name: acs-first-review
description: Review code for correctness and useful tests.
---
Review the current changes for correctness and missing behavioral tests.
SKILL
```

If the child directory already exists, the command stops before writing it.
Use your existing Skill or choose another name. A Skill is material visible to
the target; selecting it does not itself prove the model will follow it.

## 3. Save a read-only Profile

Run from a real interactive terminal:

```sh
acs devin create-profile --name first-review
```

Despite its name, this builder does not start Devin or require a Devin account.
It creates a common v3 Profile with a Devin overlay that also works with the
sandbox shell and generic commands.

1. Open **Skills**, select `acs-first-review` with Space/Enter, then return
   with Left/Esc. `/` searches; Esc while searching clears the filter.
2. Leave **Workspace** read-only for this first run. Choose **Read and write
   (coding work)** only when you intend the target to modify the workspace.
3. Choose **Create Profile**. If you skipped the Skill, confirm the empty
   selection when prompted. Empty selections still have workspace/runtime/Session
   authority; they do not mean zero access.

Ctrl+C cancels with exit 130; a changed draft may require discard confirmation.
An existing Profile name is never overwritten. Use another name or
`acs profile edit first-review`. Restart the builder if you add a Skill while it
is open.

A Profile stores selections under `~/.acs/profiles`, not copies of Skill files.
Removing or renaming selected source material can make a later launch fail.

## 4. Inspect and launch from your workspace

Change into the project directory you want to inspect. The **current directory**
is the workspace; the Profile name does not bind it to a particular repository.
Then run:

```sh
acs profile show first-review --json
acs profile validate first-review
acs explain sandbox --profile first-review
acs sandbox --profile first-review --dry-run
acs sandbox --profile first-review
```

- `show` reads stored structure, including missing selections
- `validate` checks structure and selected Skill sources, not complete launch readiness
- `explain` describes effective authority; native readiness is unchecked unless requested
- Sandbox dry-run resolves the plan and checks bounded native readiness, without a Session
- The final command starts `/bin/zsh -f` inside a private **Session**

Inside the shell, try:

```sh
pwd
printf '%s\n' "$HOME"
find "$HOME" -maxdepth 8 -type f
exit
```

You should see your workspace as the current directory and a synthetic Session
home containing the selected common material. No Devin credential is copied for
this shell. `exit` returns to your original terminal. ACS removes the Session
only after its contained process tree is proven settled.

The workspace is read-only for this new Profile, but the private Session is
writable and outbound network access is permitted. Read the
[security boundaries](security-model.md) before using sensitive projects.

## 5. Choose a target

### Devin

Install and authenticate Devin separately using its own supported instructions.
Its executable must be discoverable on your host `PATH`, and its credential is
read from `~/.local/share/devin/credentials.toml`. ACS copies only that allowlisted
credential for a Devin launch.

```sh
acs doctor --target devin
acs devin --profile first-review --dry-run
acs devin --profile first-review
```

Selected common instructions become ACS-managed Devin rules. Repository-local
Skills and other target-owned workspace content remain Devin's responsibility;
a selected global Skill catalog is not a complete filter of workspace content.
See [target conformance](shared-target-conformance.md).

### Codex

ACS supports exactly `codex-cli 0.149.1` for this integration. A newer installed
Codex is not automatically compatible. Install that target separately, use a
normal macOS terminal with an available Keychain, and create an ACS-owned named
ChatGPT identity:

```sh
acs doctor --target codex-auth
acs codex auth login --name work
acs codex create-profile --name codex-review --auth work
acs codex --profile codex-review --dry-run
acs codex --profile codex-review
```

Select Skills and workspace access in this separate builder. The earlier Devin
Profile does not have a Codex overlay; do not just substitute its name here.
For one Profile with both overlays, use the
[common Profile format](common-profile-format.md) and
[declarative creation](profiles.md#declarative-creation).

Credentials live in an ACS-specific macOS Keychain namespace, not the Profile.
ACS does not import or fall back to your global Codex login. Login/status and
real launch access the named identity; Codex dry-run does not access Keychain,
probe the target, or establish authentication readiness. Follow
[named authentication](codex.md#named-authentication) for device login, status, recovery, and logout.

### A generic command

No AI target or account is required:

```sh
acs run --profile first-review -- /usr/bin/git status
```

The `--` is required. ACS runs literal arguments without inserting a shell;
bare names search only `/usr/local/bin:/usr/bin:/bin`, not your host `PATH`.
This command uses common capabilities and no target credentials or overlay.
See [generic commands](generic-run.md) for scripts and runtime dependencies.

## When something fails

1. Check `acs version`, `command -v acs`, and contextual `--help` for the binary
   you are actually running
2. Use `acs doctor --target sandbox`, `acs profile show NAME --json`, and
   `acs profile validate NAME` to distinguish host, stored-data, and Skill-source problems
3. For retained state, use `acs session list` and the printed recovery guidance;
   do not delete Sessions, transaction journals, or Keychain records manually
4. Review [troubleshooting](troubleshooting.md) and
   [manual recovery](manual-upgrade-recovery.md) before retrying an uncertain mutation

Next: [edit or clone a Profile](profiles.md#mutations),
[share sanitized intent](portable-profile-exchange.md), or
[understand the architecture](architecture.md).

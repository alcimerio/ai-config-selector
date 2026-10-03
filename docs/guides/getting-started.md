# Get started with ACS

[Documentation index](../README.md) · [CLI guide](../reference/cli.md) · [Security model](../reference/security-model.md)

Start with a credential-free shell on macOS 26 Apple Silicon to inspect
workspace access and the temporary home before adding an AI target or account.
For an installed release, use the documentation at its Git tag.

## 1. Install and check the host

Follow the [release installation](../../README.md#install) or
[source build](../../README.md#build-from-source) instructions. In the same terminal:

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

A Skill is a local bundle with a `SKILL.md` entry file. ACS discovers immediate
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

If the child directory already exists, the command stops before writing it. Use
your existing Skill or choose another name. Selecting a Skill makes its files
visible to the target. Model behavior still depends on the target and the
instructions.

## 3. Save a read-only Profile

Run from a real interactive terminal:

```sh
acs devin create-profile --name first-review
```

Despite its name, this builder does not start Devin or require a Devin account.
It creates a common v3 Profile with a Devin overlay that also works with the
sandbox shell and generic commands.

1. Open Skills, select `acs-first-review` with Space/Enter, then return
   with Left/Esc. `/` searches; Esc while searching clears the filter.
2. Leave Workspace read-only for this first run. Choose Read and write
   only when you intend the target to modify the workspace.
3. Choose Create Profile. If you skipped the Skill, confirm the empty
   selection when prompted. Empty selections still have workspace/runtime/Session
   authority; they do not mean zero access.

Ctrl+C cancels with exit 130; a changed draft may require discard confirmation.
An existing Profile name is never overwritten. Use another name or
`acs profile edit first-review`. Restart the builder if you add a Skill while it
is open.

A Profile stores selections under `~/.acs/profiles`, not copies of Skill files.
Removing or renaming selected source material can make a later launch fail.

## 4. Inspect and launch from your workspace

Change into the project directory you want to inspect. The current directory
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
- The final command starts `/bin/zsh -f` inside a private Session

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
[security boundaries](../reference/security-model.md) before using sensitive projects.

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
See [target conformance](../reference/shared-target-conformance.md).

### Codex or a generic command

Follow [interactive Codex](codex.md#interactive-launch) for its supported target
version, separate Profile overlay and ACS-owned named ChatGPT login. ACS does
not import or fall back to global Codex authentication.

To run without an AI target or account:

```sh
acs run --profile first-review -- /usr/bin/git status
```

See [generic commands](generic-run.md) for literal argv, the required `--`, fixed
search path and runtime dependencies. This path uses common capabilities without
a target overlay or copied target credentials.

## When something fails

1. Check `acs version`, `command -v acs`, and contextual `--help` for the binary
   you are actually running
2. Use `acs doctor --target sandbox`, `acs profile show NAME --json`, and
   `acs profile validate NAME` to distinguish host, stored-data, and Skill-source problems
3. For retained state, use `acs session list` and the printed recovery guidance;
   do not delete Sessions, transaction journals, or Keychain records manually
4. Review [troubleshooting](troubleshooting.md) and
   [manual recovery](manual-upgrade-recovery.md) before retrying an uncertain mutation

To reuse this setup, [edit or clone a Profile](profiles.md#mutations). Use
[portable exchange](portable-profile-exchange.md) to share sanitized selections.
For implementation details, read the [architecture](../development/architecture.md).

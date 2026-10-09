<h1 align="center">AI Config Selector</h1>

<p align="center">
  Reusable, sandboxed capability Profiles for AI coding CLIs on macOS.
</p>

<p align="center">
  <a href="https://github.com/alcimerio/ai-config-selector/releases/latest"><img src="https://img.shields.io/github/v/release/alcimerio/ai-config-selector?sort=semver" alt="Latest release"></a>
  <a href="https://github.com/alcimerio/ai-config-selector/actions/workflows/ci.yml"><img src="https://github.com/alcimerio/ai-config-selector/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/alcimerio/ai-config-selector/actions/workflows/macos.yml"><img src="https://github.com/alcimerio/ai-config-selector/actions/workflows/macos.yml/badge.svg?branch=main" alt="macOS validation"></a>
  <img src="https://img.shields.io/badge/platform-macOS%2026%20%7C%20Apple%20Silicon-black?logo=apple" alt="Platform: macOS 26 on Apple Silicon">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/alcimerio/ai-config-selector" alt="MIT License"></a>
</p>

AI Config Selector (`acs`) is a Go CLI that runs Devin, Codex, a shell, or any
command inside the native macOS Seatbelt sandbox. Run directly, a coding agent
can usually reach your whole home directory, every installed Skill and any
credentials it finds. ACS makes that access explicit and repeatable: save the local
Skills, instruction files, filesystem permissions, environment references and
local MCP servers a tool may use in a reusable Profile, then launch it from any
project.

[Get started](docs/guides/getting-started.md) · [Documentation](docs/README.md) ·
[Security boundaries](docs/reference/security-model.md) · [Contribute](CONTRIBUTING.md)

> [!IMPORTANT]
> ACS supports macOS 26 on Apple Silicon (`darwin/arm64`). Linux and Intel Macs
> are not supported runtimes. Devin and Codex are installed separately; you can
> try the sandbox without an AI account.

## Why ACS?

- **Explicit access.** New v3 Profiles default to a read-only workspace; write
  access and extra paths are opt-in. See [Profiles](docs/guides/profiles.md).
- **One Profile, many targets.** The same selections drive Devin, Codex, a
  sandbox shell or a [literal command](docs/guides/generic-run.md), from any
  project directory.
- **Inspect before you launch.** `acs explain` reports requested and effective
  authority, and `--dry-run` plans a launch without starting a Session. See
  [Diagnostics](docs/guides/diagnostics.md).
- **Local Skills and MCP servers.** Select Skill bundles and local STDIO
  [MCP servers](docs/guides/mcp-profiles.md) per Profile.
- **History and sharing.** Compare and restore [Profile revisions](docs/guides/profile-history.md)
  and [export sanitized selections](docs/guides/portable-profile-exchange.md)
  without host paths or credentials.
- **Fail closed.** A launch runs inside the sandbox or not at all, and
  [retained Sessions](docs/guides/session-operations.md) are recovered only
  after cleanup is proven.

## How it works

```text
Profile ──► immutable authority plan ──► private Session ──► Seatbelt sandbox ──► target
(saved      (resolved before any         (synthetic home,      (macOS native,       devin | codex |
selections)  Session exists)              selected material)    no fallback)         /bin/zsh -f | your command
```

| Term | Meaning |
| --- | --- |
| **Profile** | Saved capability selections under `~/.acs/profiles`: Skills, instructions, workspace and path access, executables, environment references, MCP servers and optional per-target overlays. It stores references, not copies of files or secret values. |
| **Skill** | A local bundle with a `SKILL.md` entry file, discovered under `~/.agents/skills` and `~/.config/devin/skills`. ACS does not install or download Skills. |
| **Session** | The private, temporary home and state for one launch. ACS removes it only after proving the contained process tree has settled. |
| **Target** | What runs inside the sandbox: Devin, Codex, the sandbox shell (`/bin/zsh -f`), or a literal command passed to `acs run`. |

The [architecture](docs/development/architecture.md) and
[security model](docs/reference/security-model.md) describe each step in detail.

## Install

Install the latest stable release:

```sh
curl -fsSL https://github.com/alcimerio/ai-config-selector/releases/latest/download/install.sh | sh
```

The installer checks your OS and architecture, verifies the archive checksum,
and installs in `~/.local/bin`. It refuses to overwrite an existing `acs`,
needs no `sudo`, and does not edit shell startup files. Add the installed
directory to this terminal's search path and verify which binary will run:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v acs
acs version
```

<details>
<summary>Inspect the installer or choose a specific release</summary>

Choose a release and copy its tag and installer SHA-256 from the
[release asset metadata](https://api.github.com/repos/alcimerio/ai-config-selector/releases/latest).
Use `tag_name` and the hexadecimal part of the `install.sh` asset's `digest`,
without the `sha256:` prefix. Replace the two input values below with those from
the same reviewed release.
Use a scratch directory without `install.sh`. Verify the downloaded installer,
inspect it (`q` exits `less`), then run it locally:

<!-- fresh-install-example -->
```sh
set -eu
release_version='vMAJOR.MINOR.PATCH'
installer_sha256='REVIEWED_INSTALLER_SHA256'
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
printf '%s  %s\n' \
  "$installer_sha256" install.sh \
  | shasum -a 256 -c -
less install.sh
sh ./install.sh
"$HOME/.local/bin/acs" version
```

</details>

<details>
<summary>Verify release provenance</summary>

Release archives and `SHA256SUMS` carry GitHub build attestations. With the
[GitHub CLI](https://cli.github.com/), from a directory holding the downloaded
release assets:

```sh
gh attestation verify acs_MAJOR.MINOR.PATCH_darwin_arm64.tar.gz --repo alcimerio/ai-config-selector
shasum -a 256 -c SHA256SUMS
```

</details>

> [!WARNING]
> Release archives are unsigned and unnotarized. SHA-256 checks byte identity
> against a trusted digest; GitHub attestations provide separate origin evidence.
> Neither is Apple approval or a malware review. Do not disable Gatekeeper,
> remove quarantine, or weaken sandbox settings to make ACS run. See
> [installation and recovery](docs/guides/manual-upgrade-recovery.md).

### Upgrading

Already have ACS? Follow the
[upgrade and recovery guide](docs/guides/manual-upgrade-recovery.md) to retain
your working binary and verify the replacement before switching. Use the manual
path when your binary has no updater.

`acs update --check` and `acs update` support direct installer layouts. Read the
upgrade guide before replacing a binary: rollback does not downgrade stored data.

### Build from source

With the Go toolchain in [go.mod](go.mod) on a supported Mac:

```sh
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
./bin/acs version
export PATH="$PWD/bin:$PATH"
```

A source build reports `acs devel` and cannot self-update. See
[Contributing](CONTRIBUTING.md) for checks and release-evidence requirements.

## Quickstart

No AI account is needed. Run these from the project you want to inspect:

```sh
acs doctor --target sandbox                 # 1. check host prerequisites
acs profile create --name first-review      # 2. save a read-only Profile
acs explain sandbox --profile first-review  # 3. see what the sandbox will allow
acs sandbox --profile first-review          # 4. open a shell inside the sandbox
```

In the builder (step 2), keep the Review preset, continue without target
overlays, and choose Create Profile for a minimal read-only run. Confirm the
empty selection. The builder requires no client or account.

The shell runs `/bin/zsh -f` without user startup files. Your workspace is the
current directory and `$HOME` is a synthetic Session home. Type `exit` to return.

To use an AI target, install and authenticate it separately and select its
target overlay in the Profile builder. Then launch it with the Profile:

```sh
acs devin --profile NAME
acs codex --profile NAME
```

Follow [Get started](docs/guides/getting-started.md) to add a Skill and continue
with Devin, [interactive Codex](docs/guides/codex.md#interactive-launch) for its
ACS-owned named login, and [target conformance](docs/reference/shared-target-conformance.md)
for integration differences.

## Common commands

| Task | Command |
| --- | --- |
| List or inspect Profiles | `acs profile list`, `acs profile show NAME --json` |
| Change a Profile | `acs profile edit NAME` |
| Explain effective access | `acs explain sandbox --profile NAME` |
| Plan a launch without a Session | `acs sandbox --profile NAME --dry-run` |
| Run a literal command | `acs run --profile NAME -- COMMAND [ARG...]` |
| Inspect or recover Sessions | `acs session list`, `acs session inspect ID`, `acs session recover ID` |
| Check for updates | `acs version`, `acs update --check` |

Use `acs help` for your binary's command grammar and the
[CLI reference](docs/reference/cli.md) for every command.

## Security boundaries

There is no unsandboxed fallback. New v3 Profiles default to read-only workspace
access; the private Session is writable. ACS removes it only after proving
process-tree cleanup, preserving uncertain state for recovery.

> [!CAUTION]
> ACS is not an egress firewall: targets can transmit data they can read.
> Selected secrets are shared with the attached process tree, including MCP servers.

Choose trusted Skills, instructions and programs. Read the
[security model](docs/reference/security-model.md) before granting access.

## Compatibility

| Platform | Status |
| --- | --- |
| macOS 26 on Apple Silicon (`darwin/arm64`) | Supported |
| Intel Macs | Not supported. Historical v0.4.0 Intel assets do not extend current support. |
| Linux | Not supported. v0.3.3 was the final Linux-supported release. |

Supported Codex versions are listed in
[target compatibility](docs/reference/target-compatibility.md).

## Project status

ACS is pre-1.0. Documentation follows this checkout and `main` can describe
changes that have not shipped; use your release tag for installed behavior and
[GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases)
for published notes and downloads.

## Help and support

Start with [troubleshooting](docs/guides/troubleshooting.md), then
[open an issue](https://github.com/alcimerio/ai-config-selector/issues/new) with a
sanitized reproduction, ACS/macOS versions and architecture. Keep credentials,
target output, Session contents and private bindings out of reports.

## Contributing

[Contributing](CONTRIBUTING.md) covers setup and PR checks;
[the documentation index](docs/README.md) lists user, reference and maintainer pages.

## License

ACS is available under the [MIT License](LICENSE).

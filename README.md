# AI Config Selector

AI Config Selector (`acs`) lets you save a named **Profile** of capabilities,
then run Devin, Codex, a shell, or a command inside a native macOS sandbox with
those capabilities. Use it to choose which Skills, files, environment variables,
and local MCP servers a coding session can access instead of inheriting your
whole host configuration.

**Supported runtime:** macOS 26 on Apple Silicon (`darwin/arm64`).
**Latest published release:** [v0.5.0](https://github.com/alcimerio/ai-config-selector/releases/tag/v0.5.0).
ACS is a Go command-line tool. It does not include Devin or Codex; install the
target you want separately. You can try the sandbox without an AI account.

[Get started](docs/getting-started.md) · [Documentation](docs/README.md) ·
[Security boundaries](docs/security-model.md) · [Contribute](CONTRIBUTING.md)

## How it works

1. **Choose a Profile.** A Profile saves references and permissions, not copies
   of credentials or Skill files. New v3 Profiles default to a read-only workspace.
2. **Launch from your project.** Your current directory becomes the workspace.
   ACS resolves the selected material and creates a private, temporary Session
   with a synthetic home and a clean environment.
3. **Work inside the sandbox.** ACS applies the required Seatbelt policy to the
   process and its descendants, then waits for cleanup proof before removing
   the Session. Uncertain cleanup is retained for conservative recovery.

The same common Profile capabilities can be used by multiple targets. Target
**overlays** add the fixed Devin or Codex integration. A Profile created for
Devin is not automatically a Codex Profile; see the
[common format](docs/common-profile-format.md) for explicit overlays.

## Install

For a **fresh installation**, download the release-pinned installer, verify its
published checksum, inspect it (`q` exits `less`), then run it locally. Use a
scratch directory that does not already contain `install.sh`:

<!-- published-v050-fresh-install-example -->
```sh
set -eu
release_version=v0.5.0
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
printf '%s  %s\n' \
  '5723249bb5d69b5878e9178e6dc7cb45812d8d6930029d8c174b5acab3a5b38f' install.sh \
  | shasum -a 256 -c -
less install.sh
sh ./install.sh
"$HOME/.local/bin/acs" version
```

The installer defaults to `~/.local/bin`, refuses to overwrite an existing
`acs`, needs no `sudo`, and does not edit shell startup files. Add the installed
directory to this terminal's search path and verify which binary will run:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v acs
acs version
```

Release archives are **unsigned and unnotarized**. SHA-256 checks byte identity
against a trusted digest; GitHub attestations provide separate origin evidence.
Neither is Apple approval or a malware review. Do not disable Gatekeeper,
remove quarantine, or weaken sandbox settings to make ACS run. See
[installation and recovery](docs/manual-upgrade-recovery.md).

### Upgrading from v0.4.0

The published v0.4.0 binary has no `acs update` command. Install v0.5.0 into a
**new, empty** user-owned directory and retain the old binary. Use a scratch
directory that does not already contain `install-v0.5.0.sh`:

<!-- published-v050-bootstrap-example -->
```sh
set -eu
release_version=v0.5.0
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
bootstrap_root="$HOME/.local/opt/acs-$release_version"
mkdir -p "$HOME/.local/opt"
test ! -e "$bootstrap_root"
mkdir -m 700 "$bootstrap_root"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install-v0.5.0.sh "$release_url/install.sh"
printf '%s  %s\n' \
  '5723249bb5d69b5878e9178e6dc7cb45812d8d6930029d8c174b5acab3a5b38f' install-v0.5.0.sh \
  | shasum -a 256 -c -
less install-v0.5.0.sh
sh ./install-v0.5.0.sh --bin-dir "$bootstrap_root"
"$bootstrap_root/acs" version
```

Before newer-format writes, finish active work and preserve private quiescent
Profile-file copies as described in the [recovery guide](docs/manual-upgrade-recovery.md).
Then deliberately select the new directory with `PATH` and check `command -v acs`.
Binary rollback does not downgrade Profiles, identities, history, or Sessions.
Keep a compatible v0.5.0 binary available for inspecting or recovering newer data.

With an existing supported v0.5.0 installer layout, `acs update --check` reads
stable-release metadata without changing files; `acs update` explicitly installs
a newer stable release. [Update and rollback limits](docs/manual-upgrade-recovery.md)
cover layout restrictions and explicit version selection. There are no background
update checks, package-manager distribution, or uninstaller.

### Build from source

With Go 1.27.1 or later on a supported Mac:

```sh
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
./bin/acs version
export PATH="$PWD/bin:$PATH"
```

A source build reports `acs devel` and cannot self-update. See
[Contributing](CONTRIBUTING.md) for checks and release-evidence requirements.

## Try a credential-free sandbox

No Devin or Codex installation is needed for this path:

```sh
acs doctor --target sandbox
acs devin create-profile --name first-review
```

The builder command is named `devin create-profile`, but does not start Devin
or require its credentials. Choose **Create Profile** and confirm the empty
selection for a minimal first run; leave Workspace read-only. Or follow the
[getting-started guide](docs/getting-started.md) to add your first Skill.

From the project directory you want to inspect:

```sh
acs profile validate first-review
acs sandbox --profile first-review --dry-run
acs sandbox --profile first-review
```

The shell is always `/bin/zsh -f`, with a synthetic home and no user startup
files. Type `exit` to return. A dry-run does not start the requested target;
its precise checks vary by command, so it is not a promise that a real launch
will succeed. [Get started](docs/getting-started.md) explains each step and how
to continue with Devin or Codex.

## Everyday commands

Use `acs help` or `acs COMMAND --help` for the exact grammar of your binary.
These examples assume a saved Profile named `first-review`:

```sh
acs profile list
acs profile show first-review --json
acs explain sandbox --profile first-review
acs profile edit first-review
acs run --profile first-review -- /usr/bin/git status
acs session list
```

- [CLI guide](docs/cli.md): command groups, grammar, diagnostics, and dry-run limits
- [Profiles](docs/common-profile-format.md): capabilities, overlays, versions, and migration
- [Devin/Codex conformance](docs/shared-target-conformance.md): common behavior and target differences
- [Interactive Codex](docs/codex.md#interactive-launch): fixed `codex-cli 0.149.1` and ACS-owned named ChatGPT login
- [Profile exchange](docs/portable-profile-exchange.md): sharing sanitized intent with explicit local bindings
- [Recovery](docs/manual-upgrade-recovery.md): interrupted writes, retained Sessions, and rollback

## Isolation and limitations

There is no unsandboxed fallback. ACS fails closed if the required native
sandbox cannot be established. New v3 Profiles make the workspace read-only
unless you explicitly select coding write; legacy v1/v2 Profiles retain their
writable-workspace behavior. The Session is writable. Additional selected path,
executable, and environment grants apply to the contained process tree.

**ACS is not an egress firewall.** Outbound IP and DNS are permitted; destination
allowlisting is research, not a shipped feature. A target can send data it is
allowed to read to an external service. Skills, instructions, MCP programs, and
workspace content still need your trust. Selected secrets are available to the
attached process tree, including local MCP servers, rather than isolated per server.

ACS does not manage plugins, hooks, custom agents, remote MCP, or arbitrary
target settings. Target-owned content inside the selected workspace can still
be discovered. [The security model](docs/security-model.md) explains these
boundaries and what to avoid sharing in bug reports.

v0.3.3 is the final release with Linux support. Linux source is retained as a
non-blocking portability observation, with no current release or support promise.
Historical v0.4.0 Intel assets do not make Intel Macs supported by v0.5.0.

## Project status and contributing

Start with the [architecture](docs/architecture.md) and [contribution guide](CONTRIBUTING.md).
The [documentation index](docs/README.md) separates current user guides,
maintainer procedures, research, and historical release records.

Release-specific changes are in the [v0.5.0 release notes](docs/releases/v0.5.0.md)
and [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases).
Maintainer verification and publication procedures live in
[Contributing](CONTRIBUTING.md). Native tests do not replace real-account or
sustained daily-use observations.

## License

ACS is available under the [MIT License](LICENSE).

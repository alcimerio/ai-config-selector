# AI Config Selector

Run coding tools with explicit access to your project and selected local resources.

AI Config Selector (`acs`) is a Go CLI that runs Devin, Codex, a shell, or a
command inside a native macOS sandbox. Save your choices of local Skills,
instruction files, filesystem permissions, environment references and local MCP
servers in a reusable Profile. Launch it from your project.

ACS supports macOS 26 on Apple Silicon (`darwin/arm64`). The latest published
release is [v0.5.1](https://github.com/alcimerio/ai-config-selector/releases/tag/v0.5.1).
Devin and Codex are installed separately. You can try the sandbox without an
AI account. Linux and Intel Macs are not supported runtimes.

[Get started](docs/guides/getting-started.md) · [Documentation](docs/README.md) ·
[Security boundaries](docs/reference/security-model.md) · [Contribute](CONTRIBUTING.md)

## What you can do

- Save separate Profiles for read-only review and coding work
- Give a target access to selected local Skills and tools in a temporary home
- Inspect effective permissions before launch
- Use the same common selections with explicit Devin and Codex overlays

## How it works

1. Choose a Profile. It stores references and permissions; credentials and
   Skill files stay in their separate source locations. New v3 Profiles default
   to a read-only workspace.
2. Launch from your project. The current directory becomes the workspace. ACS
   resolves the selections and creates a private, temporary Session with a
   synthetic home and a clean environment.
3. Work inside the sandbox. ACS applies the Seatbelt policy to the process and
   its descendants. It removes the Session after proving cleanup, or retains
   it for recovery when cleanup is uncertain.

Target overlays add the fixed Devin or Codex integration. A Devin Profile
is not automatically a Codex Profile; see the
[common format](docs/reference/common-profile-format.md) for explicit overlays.

## Install

For a fresh installation, download the release-pinned installer, verify its
published checksum, inspect it (`q` exits `less`), then run it locally. Use a
scratch directory that does not already contain `install.sh`:

<!-- published-v051-fresh-install-example -->
```sh
set -eu
release_version=v0.5.1
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
printf '%s  %s\n' \
  'd1e899c9cc20e85450572f350986f8e1e68fdd649ee184b497bc05160e02f655' install.sh \
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

Release archives are unsigned and unnotarized. SHA-256 checks byte identity
against a trusted digest; GitHub attestations provide separate origin evidence.
Neither is Apple approval or a malware review. Do not disable Gatekeeper,
remove quarantine, or weaken sandbox settings to make ACS run. See
[installation and recovery](docs/guides/manual-upgrade-recovery.md).

### Upgrading

Already have ACS? Follow the
[upgrade and recovery guide](docs/guides/manual-upgrade-recovery.md) to retain
your working binary and verify the replacement before switching. v0.4.0 has no
updater; the guide includes that bootstrap path.

For supported v0.5.x installer layouts, `acs update --check` checks stable-release
metadata without changing files, and `acs update` installs a newer stable release.
Binary rollback does not downgrade stored data. There are no background update
checks, package-manager distribution, or uninstaller.

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

To try the sandbox without installing Devin or Codex:

```sh
acs doctor --target sandbox
acs devin create-profile --name first-review
```

The builder command is named `devin create-profile`, but does not start Devin
or require its credentials. Choose Create Profile and confirm the empty
selection for a minimal first run. Leave Workspace read-only. Or follow the
[getting-started guide](docs/guides/getting-started.md) to add your first Skill.

From the project directory you want to inspect:

```sh
acs profile validate first-review
acs sandbox --profile first-review --dry-run
acs sandbox --profile first-review
```

The shell is always `/bin/zsh -f`, with a synthetic home and no user startup
files. Type `exit` to return. A dry-run does not start the requested target;
its precise checks vary by command, so it is not a promise that a real launch
will succeed. [Get started](docs/guides/getting-started.md) explains each step and how
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

- [CLI guide](docs/reference/cli.md): command groups, grammar, diagnostics, and dry-run limits
- [Profiles](docs/reference/common-profile-format.md): capabilities, overlays, versions, and migration
- [Devin/Codex conformance](docs/reference/shared-target-conformance.md): common behavior and target differences
- [Interactive Codex](docs/guides/codex.md#interactive-launch): fixed `codex-cli 0.149.1` and ACS-owned named ChatGPT login
- [Profile exchange](docs/guides/portable-profile-exchange.md): sharing sanitized intent with explicit local bindings
- [Recovery](docs/guides/manual-upgrade-recovery.md): interrupted writes, retained Sessions, and rollback

## Isolation and limitations

There is no unsandboxed fallback. ACS fails closed if the required native
sandbox cannot be established. New v3 Profiles make the workspace read-only
unless you explicitly select coding write; legacy v1/v2 Profiles retain their
writable-workspace behavior. The Session is writable. Additional selected path,
executable, and environment grants apply to the contained process tree.

ACS is not an egress firewall. Outbound IP and DNS are permitted; destination
allowlisting is research, not a shipped feature. A target can send data it is
allowed to read to an external service. Skills, instructions, MCP programs, and
workspace content still need your trust. Selected secrets are available to the
attached process tree, including local MCP servers, rather than isolated per server.

ACS does not manage plugins, hooks, custom agents, remote MCP, or arbitrary
target settings. Target-owned content inside the selected workspace can still
be discovered. [The security model](docs/reference/security-model.md) explains these
boundaries and what to avoid sharing in bug reports.

v0.3.3 is the final release with Linux support. The Linux/Bubblewrap sandbox
backend has been removed; portable source checks do not imply runtime support.
Historical v0.4.0 Intel assets do not make Intel Macs supported by v0.5.0.

## Contributing and getting help

Bug reports, documentation fixes, and focused pull requests are welcome.

- Start with [Contributing](CONTRIBUTING.md) for setup, development rules, and checks
- Read the [architecture](docs/development/architecture.md) before changing execution or containment
- Check [troubleshooting](docs/guides/troubleshooting.md), then [open an issue](https://github.com/alcimerio/ai-config-selector/issues/new)
  with your ACS version, macOS version, and a minimal sanitized reproduction
- Discuss changes to permissions or supported targets in an issue before implementing them

Do not post credentials, target output, Session contents, private paths,
environment values, or generated sandbox policy. See the
[security model](docs/reference/security-model.md) for reporting guidance.

## Documentation and releases

The [documentation index](docs/README.md) separates user guides, maintainer
procedures, research, and historical records. Start with the
[walkthrough](docs/guides/getting-started.md) for Devin or Codex setup.

See [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases)
for published artifacts and release notes. Documentation on `main` can describe
changes that have not shipped; use the documentation at your release tag when
checking release behavior. Native tests cover their documented scenarios.
Real-account operation and sustained daily use require separate observations.

## License

ACS is available under the [MIT License](LICENSE).

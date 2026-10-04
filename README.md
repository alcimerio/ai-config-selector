# AI Config Selector

Run coding tools with explicit access to your project and selected local resources.

AI Config Selector (`acs`) is a Go CLI that runs Devin, Codex, a shell, or a
command inside a native macOS sandbox. Save your choices of local Skills,
instruction files, filesystem permissions, environment references and local MCP
servers in a reusable Profile. Launch it from your project.

ACS supports macOS 26 on Apple Silicon (`darwin/arm64`). Get the
[latest stable release](https://github.com/alcimerio/ai-config-selector/releases/latest).
Devin and Codex are installed separately. You can try the sandbox without an
AI account. Linux and Intel Macs are not supported runtimes.

[Get started](docs/guides/getting-started.md) · [Documentation](docs/README.md) ·
[Security boundaries](docs/reference/security-model.md) · [Contribute](CONTRIBUTING.md)

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

Release archives are unsigned and unnotarized. SHA-256 checks byte identity
against a trusted digest; GitHub attestations provide separate origin evidence.
Neither is Apple approval or a malware review. Do not disable Gatekeeper,
remove quarantine, or weaken sandbox settings to make ACS run. See
[installation and recovery](docs/guides/manual-upgrade-recovery.md).

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

## First run

Run from the project you want to inspect. Keep the Review preset, continue
without target overlays, and choose Create Profile for a minimal read-only run.
Confirm the empty selection. The builder requires no client or account:

```sh
acs doctor --target sandbox
acs profile create --name first-review
acs sandbox --profile first-review
```

The shell runs `/bin/zsh -f` without user startup files. Type `exit` to return.
Follow [Get started](docs/guides/getting-started.md) to add a Skill, inspect access
before launch and continue with Devin or Codex. Use `acs help` for your binary's
command grammar and [target conformance](docs/reference/shared-target-conformance.md)
for integration differences.

## Security boundaries

There is no unsandboxed fallback. New v3 Profiles default to read-only workspace
access; the private Session is writable. ACS removes it only after proving
process-tree cleanup, preserving uncertain state for recovery.

ACS is not an egress firewall: targets can transmit data they can read.
Selected secrets are shared with the attached process tree, including MCP servers.
Choose trusted Skills, instructions and programs. Read the
[security model](docs/reference/security-model.md) before granting access.

## Help and development

Start with [troubleshooting](docs/guides/troubleshooting.md), then
[open an issue](https://github.com/alcimerio/ai-config-selector/issues/new) with a
sanitized reproduction, ACS/macOS versions and architecture. Keep credentials,
target output, Session contents and private bindings out of reports.

[Contributing](CONTRIBUTING.md) covers setup and PR checks;
[the documentation index](docs/README.md) lists user, reference and maintainer pages.
Documentation follows this checkout; use your release tag for installed behavior
and [GitHub Releases](https://github.com/alcimerio/ai-config-selector/releases)
for published notes and downloads. v0.3.3 was the final Linux-supported release;
historical Intel assets do not extend current Apple Silicon support.

## License

ACS is available under the [MIT License](LICENSE).

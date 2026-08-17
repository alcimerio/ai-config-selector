# AI Config Selector

AI Config Selector (ACS) manages named capability Profiles for AI coding CLIs.
Choose a Profile when you launch a supported CLI to control which capabilities
it receives without changing its real global installation.

ACS separates shared Profile behavior from target-specific CLI adapters. The
`v0.2.0` preserves one adapter, Devin, and one Profile Component Category,
Skills, while adding downloadable binaries for the supported macOS and Ubuntu
targets. Until the v0.2.0 release checklist is complete and the immutable
Release is public, v0.1.0 remains the latest supported release.

## Supported scope

The v0.2.0 support contract defines these Supported Platforms:

- macOS 26;
- Ubuntu 24.04 LTS;

and these Supported Release Targets:

- `darwin/arm64`;
- `darwin/amd64`;
- `linux/amd64`;
- `linux/arm64`.

On every Supported Platform, ACS supports:

- the Devin CLI, installed and authenticated;
- user-global Skills discovered from Devin and shared-agent locations;
- interactive Profile creation, persistence, and dry-run inspection;
- Seatbelt-contained interactive launches on macOS 26;
- Bubblewrap-contained interactive launches on Ubuntu 24.04 LTS.

The Profile Builder requires confirmation before it creates an empty Profile.
Windows, WSL, other Linux distributions, and other operating-system or
architecture pairs are not supported by v0.2.0.

## Install

After the v0.2.0 GitHub Release is public, use its release-specific installer.
Download the installer as a file, inspect it, and only then run the local copy:

```sh
release_version=v0.2.0
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/$release_version"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output install.sh "$release_url/install.sh"
less install.sh
sh ./install.sh
"$HOME/.local/bin/acs" version
```

For the default destination, the last command must print exactly:

```text
acs v0.2.0
```

The installer selects only a Supported Release Target, downloads that target's
release-pinned archive and `SHA256SUMS`, verifies SHA-256 before extraction,
validates the archive and its exact version, and places `acs` atomically. It
defaults to `~/.local/bin`. To choose a different existing or creatable
user-writable absolute directory, run `sh ./install.sh --bin-dir /absolute/path`.
It refuses to replace an existing `acs` file.

If the selected directory is not on `PATH`, the installer prints an `export
PATH=...` command for the current shell. Review and run that command yourself;
the installer does not edit shell startup files. It does not use `sudo`.
For the default destination, the equivalent current-shell command is:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

The Supported Install Path does not pipe network content into a shell. ACS has
no supported package-manager installation, automatic update, self-update, or
uninstaller. To upgrade, repeat this flow with the exact newer release tag. To
remove ACS, the user is responsible for removing the installed binary and any
data they intentionally no longer need.

### Verify a downloaded archive independently

Set `archive` to the file for your Supported Release Target, then download it
and the manifest from the same release-specific URL. On macOS:

```sh
archive=acs_0.2.0_darwin_arm64.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" "$release_url/$archive"
curl --fail --location --proto '=https' --tlsv1.2 --output SHA256SUMS "$release_url/SHA256SUMS"
awk -v selected="$archive" '$2 == selected { print }' SHA256SUMS | shasum -a 256 --check -
```

On Ubuntu, use the same commands with the matching `linux` archive and replace
the final command with:

```sh
awk -v selected="$archive" '$2 == selected { print }' SHA256SUMS | sha256sum --check -
```

After installing the GitHub CLI, verify GitHub build provenance for an archive
or the checksum manifest with:

```sh
gh attestation verify "$archive" --repo alcimerio/ai-config-selector
gh attestation verify SHA256SUMS --repo alcimerio/ai-config-selector
```

The tag workflow attests the four archives and `SHA256SUMS`; it does not attest
`install.sh`. A successful attestation identifies the GitHub repository and
workflow that produced bytes. It does not prove that the source is safe, that
an archive is free of malware, or that Apple signed or notarized a macOS
binary. SHA-256 proves only that the archive matches the independently obtained
manifest.

### Build a development binary

Clone the repository and build the CLI from a local checkout:

```bash
git clone https://github.com/alcimerio/ai-config-selector.git
cd ai-config-selector
go build -o ./bin/acs ./cmd/acs
./bin/acs version
```

A local checkout does not carry qualifying release metadata, so the final
command prints `acs devel` instead of a release version. It is a source-built
development binary, not a Supported Release binary, even when built on a
Supported Platform. Source installation requires Go 1.25 or later and is
separate from the Supported Install Path. The examples below use `acs`;
substitute `./bin/acs` when running a local build.

## Current adapter: Devin

The `devin` command selects the supported CLI adapter. The adapter discovers
user-global Skills from:

```text
~/.config/devin/skills/
~/.agents/skills/
```

### Create a Profile

Create a named Profile for Devin:

```bash
acs devin create-profile --name backend-review
```

ACS opens a keyboard-driven Profile Builder. Its overview lists the supported
categories and their selection counts. Open Skills with Enter, Space, or
Right; use Space or Enter to select bundles; use `/` to search; then return to
the overview with Left or Escape and choose Create Profile. The Builder keeps
each category's state while you navigate.

Catalog discovery starts when Skills is first opened. A failed load offers
Retry and Back. Creating an empty Profile or saving after a category load
failure requires explicit confirmation. Saving and cancellation preserve the
draft across recoverable errors, and changed drafts require confirmation
before they are discarded.

Every screen shows its valid keys. If the terminal is smaller than 64 columns
by 18 rows, resize it to restore the active screen without losing the draft.
`Ctrl+C`, Escape on the overview, and Cancel share the same discard flow. ACS
stores a completed Profile under `~/.acs/profiles/` and prints cancellation
only after restoring the terminal.

Profile names contain 1 to 64 letters, numbers, dots, underscores, or hyphens
and must start with a letter or number. ACS will not overwrite an existing
Profile.

### Inspect a launch

Use a dry run to inspect the selected global Skills, their planned Session
paths, any repository-local Skills that Devin may inherit, and whether the
required native sandbox is ready:

```bash
acs devin --profile backend-review --dry-run
```

A dry run reports the required `native` sandbox mode, selected backend
(Seatbelt or Bubblewrap), the exact Supported Platform result, and backend
readiness. It does not create a Session or start Devin. Backend readiness may
run a fixed native capability check, but it never executes Devin or reads a
Devin credential.

### Launch Devin

Launch Devin with the Profile:

```bash
acs devin --profile backend-review
```

On macOS 26, this command runs every Devin preflight, interactive process, and
descendant inside Seatbelt. ACS verifies the root-owned system
`/usr/bin/sandbox-exec`, builds a default-deny policy from validated runtime
paths, and applies that policy to the complete process tree.

On Ubuntu 24.04, this command runs every Devin probe and the interactive
process through `/usr/bin/bwrap`. ACS requires the root-owned, non-writable
executable recorded as installed by the signed Ubuntu `bubblewrap` package and
checks that its package architecture matches ACS, its payload still matches
dpkg's packaged checksums, and unprivileged user namespaces work before leasing
a Session. This is an offline package-integrity boundary, not protection from a
compromised administrator: the package database and packaged checksums are
controlled by root. If Bubblewrap is missing or unsafe, ACS reports
`backend_unavailable` before it leases a Session or starts Devin. Review the
configured signed apt sources, then an administrator can install or repair the
package with:

```sh
sudo apt-get update && sudo apt-get install --reinstall bubblewrap
```

ACS neither bundles Bubblewrap nor downloads it at runtime.
If host AppArmor policy blocks unprivileged user namespaces, ACS reports
`sandbox_verification_failed`; administrators must review and enable an
appropriate targeted Bubblewrap profile. ACS
does not disable the global AppArmor restriction or run without
containment.

The Bubblewrap namespace exposes the workspace and Session as writable,
including Session-local temporary storage. Named runtime inputs and the
minimal operating-system runtime are read-only. The host home and host Unix
sockets are absent. Devin retains outbound IP networking, but ACS does not
mount host SSH, Docker, proxy, or agent sockets. There is no unsandboxed
fallback on either platform. ACS will not start Devin without the required
sandbox.

### Launch failure categories

ACS reports fixed, actionable categories without including generated policy,
private paths, credentials, account values, environment entries, backend
diagnostics, Devin command output, or terminal control characters:

- `unsupported_platform`: the detected host is outside the supported macOS 26
  or Ubuntu 24.04 target matrix.
- `backend_unavailable`: the required native backend is missing, modified, or
  unsafe.
- `policy_rejected`: the generated Seatbelt policy was rejected before Devin
  could start.
- `sandbox_verification_failed`: the native backend did not pass its fixed
  capability verification.
- `skill_preflight_failed` and `authentication_preflight_failed`: existing
  Devin Skills or login state could not be verified inside the sandbox.
- `devin_exited`: a normal or signaled Devin exit retains its existing exit
  code; inspect the attached Devin terminal output for target diagnostics.

Normal Devin output remains attached to the terminal, and a normal or
signaled Devin exit retains its existing exit-code behavior. ACS does not add
an additional CLI diagnostic for that ordinary target exit.

### Session lifecycle

On every Supported Platform, the command first completes sandbox preflight,
then creates an ephemeral Session with a synthetic home, copies the selected
Skill Bundles and existing Devin credential into that
Session, verifies the selection and authentication state, and starts Devin in
the current working directory through the native sandbox. ACS removes a leased
Session after launch setup fails, or only after the sandboxed process tree has
exited or been terminated and containment is settled. A failure before the
Session lease does not create Session data.

Repository-local Skills remain under Devin's control. ACS reports them during
a dry run but does not copy, filter, or isolate them.

### Native candidate gate

The release candidate is built once and its immutable supplied bytes are
installed and exercised as a black box on every Supported Release Target:
macOS 26 `darwin/arm64` and `darwin/amd64`, plus Ubuntu 24.04 LTS
`linux/amd64` and `linux/arm64`. Each native candidate gate checks backend
readiness; allowlisted and denied filesystem, environment, descriptor, socket,
and IP behavior; Skill and authentication preflight; descendants; terminal
signals, resize, and exit; and Session cleanup for concurrent and abandoned
launches. It also proves that a missing required backend or unsafe native
launch input cannot start the fixture target.

The gate records only a fixed, sanitized target/backend compatibility
observation: macOS requires the verified system Seatbelt backend, while Ubuntu
requires the verified signed-system Bubblewrap package and targeted AppArmor
profile. Candidate bytes are never rebuilt in those native jobs. Native job
summaries and artifacts exclude credentials, account data, target output,
Session contents, private paths, generated policies, environment values, and
terminal control characters.

The optional authenticated smoke remains a maintainer confidence check. It is
supplemental to, and cannot replace, the credential-free native candidate gate.

## Profiles and compatibility

ACS follows semantic versioning, but releases before `v1.0.0` may change CLI
or Profile compatibility in a new minor release. Patch releases within the
same minor line are intended to remain backward compatible. Install explicit
versions and read their release notes before upgrading.

ACS `v0.1.0` writes Profile envelope version 2 and supports loading version-1
Profiles by normalizing them in memory without rewriting their files. An older
Profile that lacks a category receives that category's empty selection, so an
upgrade does not enable capabilities. ACS can add an empty category to the
version-2 envelope without bumping the envelope version. Each category owns
and evolves its independent `schemaVersion`. ACS rejects unsupported schemas
and unknown categories.

v0.2.0 preserves the v0.1.0 Profile envelopes, category schemas, public
commands, accepted messages, file permissions, and atomic Profile persistence.
It also preserves Profile Builder behavior, Devin Adapter discovery and
preflight behavior, launch and signal handling, ACS Home at `~/.acs`, and the
intended per-launch Session creation and cleanup contract. That contained
Session lifecycle is available through Seatbelt on macOS and Bubblewrap on
Ubuntu.
Existing v0.1.0 Profiles do not require migration.

## Known limitations

- v0.2.0 macOS binaries are unsigned and unnotarized. Gatekeeper may block or
  warn about them because they do not carry an Apple Developer ID signature or
  notarization ticket. Checksums and GitHub attestations do not change that
  trust decision or represent Apple malware review. Do not weaken host security
  to treat those mechanisms as Gatekeeper approval.
- Devin is the only production CLI Adapter.
- Skills is the only production Profile Component Category.
- Profiles cannot be listed, edited, deleted, imported, or exported through
  the CLI.
- ACS does not filter repository-local Skills.
- Interactive launches require a certified native backend. Bubblewrap is
  active on Ubuntu 24.04 and Seatbelt is active on macOS 26. The synthetic
  home complements the OS sandbox and is not a substitute for native
  enforcement.
- ACS does not manage MCP servers, hooks, instructions, agents, or arbitrary
  target settings.
- ACS has no package-manager distribution, automatic updates, or uninstaller.

Read [the architecture document](docs/architecture.md) for the domain model,
module boundaries, lifecycle, schema, and security properties.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, verification commands,
the opt-in real-Devin integration test, and release validation procedure.

## License

ACS is available under the [MIT License](LICENSE).

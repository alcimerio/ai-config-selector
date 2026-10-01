# Security model and trust boundaries

[Documentation index](README.md) · [Architecture](architecture.md) · [Troubleshooting](troubleshooting.md)

This guide describes the v0.5.0/current-source boundary on macOS 26 Apple Silicon.
It is a user-facing summary, not a claim of a complete security audit or proof
that arbitrary hostile code is harmless.

## What ACS controls

ACS starts the selected target through a required native Seatbelt sandbox and
applies the policy to its descendants. It verifies the trusted system backend,
constructs a clean environment and synthetic home, projects selected material,
and owns process settlement and Session cleanup. There is no unsandboxed fallback.

For new v3 Profiles:

- The current workspace is read-only unless you explicitly select coding write
- The private Session home and temporary storage are writable
- Explicit path selections add bounded filesystem access; a directory grant
  covers its descendants and reachable hard links
- Executable selections add visibility; they are not an exclusive command allowlist
- Explicit environment selections are resolved at launch; Profile files retain
  references rather than their values
- Selected local STDIO MCP servers run within the attached process tree and its authority

Legacy v1/v2 Profiles retain writable-workspace authority. An ordinary edit does
not silently migrate their placement or authority to v3. Inspect effective
permissions with `acs explain TARGET --profile NAME` and read the
[common capability contract](common-profile-format.md).

## What remains trusted or outside the boundary

### Network destinations and data disclosure

**ACS is not an egress firewall.** Coarse outbound IP and DNS access are allowed.
If a target can read a file, selected secret, credential projection, or prompt,
it may be able to send that data to its provider or another network destination.
Read-only means no filesystem writes to that grant, not no disclosure.
Destination filtering is not a shipped capability. Native transport experiments
do not extend the production network contract.

### Code and instructions inside the Session

Choose trusted Skills, instruction files, executable tools, and local MCP servers.
ACS controls the OS-level authority they receive; it does not establish that their
contents are benign, useful, or correctly followed by a model. The selected workspace
is also readable target input and can contain target-owned project configuration.
ACS does not currently manage plugins, hooks, custom agents, or remote MCP.
Selecting their files does not activate them as ACS-managed extensions. The fixed
Codex recipe disables plugins; target-owned project discovery is a separate boundary.

MCP tool-name filtering and agent permission modes are target behavior, not
independent ACS containment or per-agent OS isolation. There is no per-MCP-server secret boundary: selected
environment values are available to the target, local servers, and descendants.
See [MCP Profiles](mcp-profiles.md) and [target conformance](shared-target-conformance.md).

### Target authentication

Devin receives only its allowlisted host credential for a Devin launch; the
sandbox-shell path does not copy that credential. Interactive Codex uses one
ACS-owned named ChatGPT identity in the macOS Keychain, projected into its private
Session. It does not fall back to global `~/.codex/auth.json` or global Codex OS-store
records. Profile files store only the named reference.

That projection is available within the selected Session's authority. Tools and
descendants running with the same authority are not isolated from it. The outer
sandbox protects unrelated host state; it does not make a target unable to use
its own selected authentication. Codex runs in a fixed externally sandboxed
no-prompt mode, with preselected Profile grants enforced by ACS and no interactive per-tool approval step.

Codex's exact version check and operation snapshot detect supported-version and
observed local-file changes; they do not authenticate arbitrary locally installed
target bytes. The CI gates separately use official checksum-locked target archives.
See [named authentication](codex.md#named-authentication) for storage, token refresh, quarantine,
and recovery semantics.

### Terminal devices

The target inherits the terminal devices explicitly attached to its standard
streams and the kernel's `/dev/tty` controlling-terminal alias. ACS derives exact
PTY device grants from the open descriptors, checks their vnode identity, and
retains private close-on-exec copies until process cleanup is proven. Redirected
files and pipes do not gain pathname permissions.

PTYs newly created inside the sandbox require macOS's ownership-tracked PTY
extension. Other terminals receive no blanket device-path or ioctl permission.
The native gate checks attached and child-created PTYs, unrelated disposable
PTY denial, and terminal input, resize, signals, and cleanup. This restriction
does not make output or terminal-control operations on the invoking terminal
harmless, or isolate tools sharing one Session's authority.

### Host races and temporary data

Filesystem grants are pathname-based. ACS validates at defined boundaries;
that is not a kernel-level promise that a cooperating same-user process can never
replace a pathname after its final check. Keep target binaries and selected material
under your control and avoid concurrent changes during launch.

Current-source Skill copying opens the selected bundle root, which may be a
symlink alias, then traverses descendants using pinned directory descriptors,
no-follow child opens, and validation of opened objects. Descendant symlinks stay
symlinks, including dangling and out-of-bundle targets; their contents are not
copied. Output files are created exclusively and retain their permission bits.

This copy assumes a private destination parent provided by Session
materialization. It rejects directory symlinks at the bundle destination and
below, but does not authenticate the initial root selection, snapshot concurrent
edits, exclude hard links or mounts, or change runtime access to copied links.
The separate allowlisted Devin credential copy still accepts symlink-backed
regular files and validates the opened input before creating output.

Session removal is logical cleanup, not a guarantee of secure physical erasure.
If ACS cannot prove that descendants and ownership have settled, it retains or
quarantines the Session. Do not force-delete that state. Use
[Session operations](session-operations.md) and the
[manual recovery guide](manual-upgrade-recovery.md).

## Release integrity and evidence

The release pipeline validates exact candidate bytes on macOS Apple Silicon and
records checksums and GitHub provenance. SHA-256 only proves identity relative to
trusted expected bytes. The archive and checksum manifest are attestation subjects;
the installer is part of the byte-matched set but is not itself an attestation subject.

Current-source release automation also requires Go vulnerability checks of the
tagged source (including tests for `darwin/arm64`, CGO disabled) and the exact
installed candidate. PR promoted-artifact CI exercises the same gates. The
scanner is pinned, but its public advisory database is live: a prior clean
result may change without a code change. Reachable source findings, binary
findings and scanner/database failures block promotion.

A source pass means no known reachable Go vulnerability was reported for that
configuration. Binary analysis is conservative and falls back to module-level
advisories when symbols are unavailable; a binary finding need not prove a
reachable call. Neither mode establishes that the entire module graph, Actions,
external target binaries or all security risks are covered. See the
[check semantics and reproduction steps](../CONTRIBUTING.md#dependency-maintenance-and-vulnerability-checks).

v0.5.0 is unsigned and unnotarized. Do not remove quarantine, disable Gatekeeper,
or weaken Seatbelt to work around a failure. A release gate is not real-account
or week-long daily-use evidence; those observations are separate evidence categories; see
[maintainer verification](../CONTRIBUTING.md#release-preparation).

## Sharing a safe bug report

For an ordinary bug, use the repository's
[issues](https://github.com/alcimerio/ai-config-selector/issues) and include the ACS
version/commit, macOS version and architecture, affected command shape, stable error
category, expected behavior, and a minimal synthetic example. Explain which checks
actually ran; a skipped native gate is not a pass.

Never attach credentials, account details, environment values, private paths,
Session contents, captured target output, or generated sandbox policy. Profile JSON
can contain private local bindings; prefer a sanitized portable export and inspect
it before sharing. Exported intent still deserves review before publication.

No private contact or vulnerability-disclosure process is documented in this
checkout. Check the repository Security tab for private reporting; if that is
unavailable, arrange a private channel with the maintainer before sending
sensitive details. Do not post a live credential or an untriaged sensitive
reproduction to a public issue. This guide does not promise a response SLA.

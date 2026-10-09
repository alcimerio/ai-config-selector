# Security policy

ACS runs coding agents and commands inside the native macOS Seatbelt sandbox.
This page explains how to report a vulnerability and which reports are in scope.
The [security model](docs/reference/security-model.md) owns the full boundary
contract.

## Supported versions

ACS is pre-1.0. Only the
[latest published release](https://github.com/alcimerio/ai-config-selector/releases/latest)
is supported; fixes are not backported to older releases. Check your binary
with `acs version` and reproduce on the latest release before reporting.

| Version | Supported |
| --- | --- |
| Latest release on macOS 26 Apple Silicon (`darwin/arm64`) | Yes |
| Older releases | No |
| Intel Macs and Linux, including historical v0.4.0 Intel and v0.3.3 Linux assets | No |

Source builds report `acs devel`. `main` can describe changes that have not
shipped; say so if your report depends on unreleased code.

## Reporting a vulnerability

Do not report a vulnerability in a public issue, pull request or discussion.

Open the repository's [Security tab](https://github.com/alcimerio/ai-config-selector/security).
If it offers **Report a vulnerability**, use it to submit a private
[GitHub Security Advisory](https://github.com/alcimerio/ai-config-selector/security/advisories/new).
If private reporting is unavailable, open an
[issue](https://github.com/alcimerio/ai-config-selector/issues/new) that asks
the maintainer for a private channel. Include no vulnerability details,
reproduction or affected component in that issue.

A useful private report includes:

- the ACS version or commit, macOS version and architecture
- the affected command shape and Profile selections, sanitized
- the expected boundary, what happened instead and the
  [security model](docs/reference/security-model.md) statement it contradicts
- a minimal synthetic reproduction and which checks actually ran

Never send live credentials, account details, environment values, private
paths, Session contents, captured target output or generated sandbox policy.
Prefer a sanitized portable Profile export to raw Profile JSON.

This policy does not promise a response time or a disclosure date.

## Scope

In scope are failures of a boundary ACS claims to enforce, for example:

- a target or descendant escaping the Seatbelt policy, or gaining filesystem
  access beyond its Profile grants and exclusions
- any path that launches a target without the sandbox; there is no unsandboxed
  fallback
- a Session receiving credentials, environment values or material that were
  not selected, or effective authority that differs from `acs explain`
- Session cleanup removing state while descendants may still be live
- installer or release-pipeline flaws that accept bytes other than the
  reviewed release

These are documented limits, not vulnerabilities on their own:

- network egress: ACS is not an egress firewall, and a target can transmit data
  it can read
- behavior of selected Skills, instructions, executables, local MCP servers and
  targets, which remain trusted
- secrets shared within one Session's process tree, including MCP servers
- pathname races by a cooperating same-user process and the absence of secure
  physical erasure
- unsigned and unnotarized release archives
- unsupported platforms

The [security model](docs/reference/security-model.md) describes each limit.
For ordinary bugs, follow [troubleshooting](docs/guides/troubleshooting.md)
and open a public issue.

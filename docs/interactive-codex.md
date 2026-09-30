# Interactive Codex

[Documentation index](README.md) · [Authentication and recovery](codex-auth.md)

The supported runtime is macOS 26 on Apple Silicon. This page describes the
current source; use the release notes for the scope of a specific artifact.

Interactive Codex is a fixed adapter for `codex-cli 0.149.1`. Create a named
ChatGPT identity first, then author a common Profile through the supported
builder:

```sh
acs codex auth login --name work
acs codex create-profile --name backend-review --auth work
acs codex --profile backend-review --dry-run
acs codex --profile backend-review
```

Use `--auth personal` on the launch command for a one-run override. The Profile
continues to contain its original opaque reference. Creation may omit `--auth`;
that Profile then requires `--auth REF` on both dry-run and real launch. A
selected Codex overlay other than version 1 fails closed, and a legacy
Devin-bound Profile is not silently upgraded into a Codex Profile.

Dry-run validates stored structure and the effective reference's syntax only.
It intentionally reports identity existence and status as unchecked and does
not touch authentication, locks, source bundles, executables, sandbox state, or
Sessions. It is useful for reviewing authority, not for proving launch
readiness.

At real launch ACS holds one named identity binding from before Session
creation until the Session-local projection is removed. The shared contained
process executor owns both the exact-version probe and interactive process,
including terminal streams, signals, resize, cancellation, descendant
settlement, cleanup, and recovery. The target receives a private synthetic
home, file-only credentials, ChatGPT-only authentication, fixed official
provider and endpoint, and untrusted project configuration. ACS applies the
Profile's read-only or coding-write workspace policy, while locked Codex runs in its supported
externally sandboxed mode (`danger-full-access` with approval policy `never`).
Codex therefore creates no nested Seatbelt profile and shows no target-owned
tool approval prompts; its full target permission remains inside the stricter
ACS outer sandbox. This is preselected Profile authority, not an ACS
per-tool approval prompt. ACS never reads global Codex authentication, imports
API keys, or falls back to another named identity.

A successful syntax-only dry-run does not establish that `work` exists, that
its Keychain item is readable, or that the installed Codex has the required
version. `acs codex auth status --name work` is a separate contained,
credential-using operation that can validate a same-identity token refresh.

Selected global Skills are first copied to the common Session materialization
and then projected to `.codex/skills/<source>/<relativePath>` without rereading
their host origins. Source identity, relative paths, modes, relative symlinks,
and collision checks are retained. Codex may additionally discover permitted
repository-local `.agents/skills` and bundled system Skills; ACS does not claim
that a workspace grant hides all unselected workspace files.

Selected instructions are copied to the common Session location, but Codex
does not receive Devin rules or an automatic Codex instruction-file projection;
see [instruction bundles](instruction-bundles.md). Explicit path, executable,
environment and MCP grants retain their [common Profile
semantics](common-profile-format.md).

The adapter deliberately has no generic argument or configuration passthrough,
backend selector, dynamic plugin authority, credential import, or API-key mode.
Current source can project explicitly selected local STDIO MCP server references;
see [MCP Profiles](mcp-profiles.md). Its isolated home, default-deny outer
sandbox, disabled stock plugin/app features, and fixed untrusted-project
decision prevent ordinary host-local and project-local MCP
configuration from becoming launch input; ACS does not claim to override every
account-service enterprise policy selected by the authenticated ChatGPT
account.
The fixed target mode is not a fallback outside containment: failure to create
or retain the ACS sandbox fails closed. Codex's own readable/writable-root
model and managed-sandbox denial messages are intentionally not the security
boundary; ACS Profile grants and lifecycle proofs are.

The projected authentication file must be readable by Codex. It is inside the
Session shared with its tools and descendants; ACS does not provide a separate
credential boundary for each helper. Outbound IP access is coarse, so readable
data can be transmitted. Treat selected Skills, commands and MCP helpers
accordingly.

An output other than exact `codex-cli 0.149.1` is an actionable compatibility
error. Real account login and target-origin refresh remain supplemental
trusted-host observations rather than credential-bearing CI requirements.
The [shared Devin/Codex behavior and evidence guide](shared-target-conformance.md)
defines the common contract, intentional projection differences and the pending
week-long real-use observation.

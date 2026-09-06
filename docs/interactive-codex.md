# Interactive Codex

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
that Profile then requires an explicit reference on every real launch. A
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
provider and endpoint, the selected read-only or coding-write sandbox, and
untrusted project configuration. ACS never reads global Codex authentication,
imports API keys, or falls back to another named identity.

Selected global Skills are first copied to the common Session materialization
and then projected to `.codex/skills/<source>/<relativePath>` without rereading
their host origins. Source identity, relative paths, modes, relative symlinks,
and collision checks are retained. Codex may additionally discover permitted
repository-local `.agents/skills` and bundled system Skills; ACS does not claim
that a workspace grant hides all unselected workspace files.

The adapter deliberately has no generic argument or configuration passthrough,
backend selector, dynamic plugin authority, credential import, or API-key mode.
An output other than exact `codex-cli 0.149.1` is an actionable compatibility
error. Real account login and target-origin refresh remain supplemental
trusted-host observations rather than credential-bearing CI requirements.

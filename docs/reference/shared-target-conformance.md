# Shared Devin and Codex behavior

[Documentation index](../README.md) · [Common Profile format](common-profile-format.md)

ACS supports common Profile capabilities across its Devin and Codex adapters on
macOS 26 Apple Silicon. Target configuration, discovery, and authentication
remain adapter-specific.

## Common intent and target differences

A version-3 Profile selects global Skills by exact `source` plus `relativePath`
identity and declares read-only or explicit read-write workspace access. Both
targets consume the same resolved common copy under `.acs/common/v1/skills`;
unselected global bundles are excluded. ACS creates the private writable
Session, applies containment and manages the process lifecycle.

| Behavior | Devin | Codex |
| --- | --- | --- |
| Selected global Skills | Projected to `.config/devin/skills` and `.agents/skills`, according to source | Projected to `.codex/skills/<source>/<relativePath>` |
| Repository-local Skills | Plan reports inherited `.devin/skills` and `.agents/skills` | Permitted workspace `.agents/skills` may be discovered by Codex; ACS does not report them as selected global material |
| Authentication | Copies only `.local/share/devin/credentials.toml` when present; verifies with contained `auth status` | Uses one ACS-owned named identity; no fallback to global Codex authentication |
| Dry run | Resolves selected material and may run the bounded sandbox-readiness probe | Checks stored structure and authRef syntax without discovery, credentials, target execution, or Session creation |

Read-only workspace access still permits project reads; it does not hide project
files or target-owned configuration. Common
[instruction bundles](common-profile-format.md#instruction-bundles) and
[local MCP references](../guides/mcp-profiles.md) also have target-specific
projections and limitations. Tool filtering and agent permissions are target
features, not separate ACS OS-level isolation.

## Use a Profile with both targets

Each interactive builder creates its own target overlay. To share one stored
Profile, explicitly include both supported version-1 overlays using
[declarative Profile creation](../guides/profiles.md#declarative-creation) and the
[common-format example](common-profile-format.md). Alternatively, create separate
Profiles with the same common selections using the
[getting-started guide](../guides/getting-started.md).

A Codex overlay stores only an opaque named authRef. `--auth` changes the
reference for one run without rewriting it or adding a missing Codex overlay.
After creating a shared Profile named `review`, compare both plans:

```sh
acs profile validate review
acs profile show review
acs explain devin --profile review
acs explain codex --profile review
acs devin --profile review --dry-run
acs codex --profile review --dry-run
```

Codex dry-run does not check whether the identity exists or works. Follow
[named authentication](../guides/codex.md#named-authentication) to create or inspect it, and never publish
credential or account output.

Legacy v1/v2 Profiles remain Devin-bound with writable workspace authority and
their established target paths. `acs profile migrate NAME` explicitly creates
a v3 common Profile; adding a Codex overlay is a separate choice. Unsupported
selected overlays or combinations fail before discovery, target execution, or
Session creation. Unknown inactive overlays remain inert; rewrite commands
refuse them when lossless preservation cannot be proved.

## Testing compatibility changes

Run the credential-free adapter and lifecycle suites when changing common
capabilities, projections, or execution:

```sh
go test ./internal/adapter ./internal/executor ./internal/codexauth ./internal/codexauthresource
```

The [adapter conformance tests](../../internal/adapter/conformance_test.go) exercise
both registries through resolution, planning, and materialization. They check
common identities, workspace intent, selected/unselected bytes, target
projections, repository inheritance, and legacy/unsupported-overlay behavior.
Executor and authentication tests cover preflight ordering, credential ownership,
Start/Wait behavior, signal forwarding, refresh eligibility, and cleanup recovery.
Portable fixtures do not establish real target discovery or native containment.

On macOS, the [native candidate gates](../../scripts/run-native-candidate-gates.sh)
exercise the supplied ACS candidate without rebuilding it. Shared-target
acceptance uses a credential-free Devin behavioral fixture to check placement,
workspace grants, unrelated-path denial, and cleanup. Separate
installed-target tests exercise the checksum-locked Devin and Codex artifacts,
real Seatbelt, PTY behavior, Keychain recovery, and descendants. Follow
[testing](../development/testing.md) for their setup; Linux or Intel results do not
establish supported native behavior.

For a compatibility bug, record the ACS version/commit and artifact SHA-256,
target version, workspace intent, stable public result, and whether the relevant
portable and native checks actually ran. Verify normal exit and interruption,
then inspect [Session state](../guides/session-operations.md) if cleanup is uncertain.
Use synthetic inputs and omit credentials, account data, target output, private
paths, environment values, and Session contents. Automated fixtures do not prove
real-account operation or sustained daily use; report those separately when
performed.

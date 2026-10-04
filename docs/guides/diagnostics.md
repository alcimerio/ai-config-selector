# Diagnose and explain a launch

[Documentation index](../README.md)

Use the command that answers your question:

- `acs profile show NAME`: inspect [stored structure](profiles.md#inspection).
- `acs doctor`: check passive host/backend prerequisites and an optional target
  executable's presence.
- `acs profile validate NAME`: validate structure and resolve selected Skills.
- `acs explain TARGET --profile NAME`: report planned permissions without
  launching; optionally check bounded native readiness.

Success applies only to the requested checks. It does not establish credentials,
executable-version compatibility, materialization or runtime enforcement.

## Passive diagnostics

```sh
acs doctor
acs doctor --target devin --json
acs doctor --json --target sandbox
acs doctor --target codex-auth
acs profile validate backend-review
acs profile validate --json backend-review
```

`doctor` needs no HOME, account, terminal or optional client. The supported host
is macOS 26 on Apple Silicon (`arm64`); Intel, Linux and other platforms fail
the platform check. It reads macOS product version through native
`kern.osproductversion`, without executing `sw_vers`.

Optional `--target` selects an executable-presence check: `devin` searches for
`devin`, `sandbox` checks `/bin/zsh`, and `codex-auth` searches for `codex` for
both named authentication and interactive launch. It does not inspect a Profile
or select a sandbox backend. Only absolute PATH entries are searched; empty and
relative entries are ignored. Candidates must resolve to readable, executable
regular files; symlinks follow runtime lookup semantics. Presence does not prove
version compatibility, including the exact reviewed CLI version requirement.

The backend check examines only `/usr/bin/sandbox-exec`: a regular, non-symlink,
root-owned file with execute bits, no group/world writes, and read/execute
access. It never invokes the Seatbelt probe. Host support and backend-file
availability are independent; a present backend cannot make an unsupported
host pass. Backend availability is unchecked on non-macOS hosts or when host
metadata is unreadable.

`profile validate` uses the [inspection codec and safe
traversal](profiles.md#inspection) for v1/v2/v3 stored structure, then resolves
only selected Skill references using Devin discovery: immediate child
directories with regular `SKILL.md` files under selected global sources.
Unselected roots are not enumerated and malformed unselected entries do not
become requirements. Empty selections need no source access. Exact source/path
identities are never rebound when removed, ambiguous, nested or differently
spelled. Symlinks follow discovery semantics; manifest bodies and complete
bundles are not validated. Restore missing bundles or edit the saved selections.

Instructions, path/executable grants, environment and MCP references receive
structural checks only. Validation does not open instruction files, inspect
grant targets, resolve environment values, start MCP servers or construct a
launch plan.

Both commands are passive. They start no subprocesses, including `--version`,
and query no credentials. They do not infer authentication from names, allocate
or recover Sessions, take locks, change permissions, migrate data or write files. Version,
authentication and enforcement remain unchecked; validation also leaves
platform, backend and executable checks unchecked. Normal launch and dry-run
behavior is unchanged.

Use `acs help doctor` or `acs help profile validate` for exact
[grammar](../reference/cli.md#grammar). Help exits 0 on stdout; invalid syntax
exits 1 with contextual stderr usage and no JSON.

### Diagnostic JSON format 1

Every syntactically valid `--json` invocation emits one compact object plus
newline on stdout, without stderr prose or color. This deterministic format is
separate from persisted schemas and inspection output. It contains exactly:

- `formatVersion`: integer `1`.
- `operation`: `doctor` or `profile.validate`.
- `target`: `""` without a doctor target, otherwise `devin`, `sandbox` or
  `codex-auth`; always `""` for validation.
- `checks`: array in the following fixed order. Each check has exactly the
  string fields `id`, `status`, `code` and `nextStep`.

| Check ID | Doctor | Profile validation |
| --- | --- | --- |
| `profile.structure` | unchecked | supported stored structure |
| `profile.sources` | unchecked | selected Skill resolution after valid structure |
| `profile.overlays` | unchecked | supported overlays, or unchecked legacy/unknown inactive overlays |
| `profile.authority` | unchecked | legacy workspace write or explicit common authority |
| `host.platform` | native metadata and supported-platform policy | unchecked |
| `backend.file` | trusted system backend-file availability on macOS | unchecked |
| `executable.availability` | selected target only; otherwise unchecked | unchecked |
| `executable.version` | unchecked | unchecked |
| `authentication` | unchecked | unchecked |
| `runtime.enforcement` | unchecked | unchecked |

`status` is `pass`, `fail` or `unchecked`. Exit 0 means all requested passive
checks passed; a requested failure or fatal prerequisite exits 1. Unchecked
facts neither pass nor independently fail the command. Structure failure leaves
source resolution unchecked (`structure_required`).

| Stable codes | Meaning |
| --- | --- |
| `not_requested` | Outside requested scope. |
| `not_probed`, `not_queried` | Version/enforcement or authentication deliberately not checked. |
| `supported_platform`, `unsupported_platform`, `platform_unavailable` | Supported metadata, unsupported host or unreadable metadata. |
| `backend_available`, `backend_unavailable`, `no_supported_backend` | Trusted backend available, unavailable/unsafe/inaccessible or unchecked on this host. |
| `executable_available`, `executable_unavailable` | Executable found or absent/unsafe/inaccessible. |
| `valid_structure` | Supported stored structure. |
| `structure_required` | Sources unchecked because structure could not be validated. |
| `legacy_workspace_write`, `explicit_common_authority` | Legacy workspace-write compatibility or explicit v3 authority; no enforcement check. |
| `legacy_implicit_target`, `supported_inactive_overlays`, `inactive_overlay_unknown` | Implicit legacy target, supported inactive overlays or unknown/unsupported inactive overlay; none selected/executed. |
| `selected_sources_resolved`, `selected_sources_unresolved`, `sources_unavailable` | Exact references resolved, missing/ambiguous or selected root cannot be enumerated. |
| Inspection failure codes | `storage_unavailable`, `invalid_name`, `missing`, `unreadable`, `non_regular`, `too_large`, `invalid_structure`, `identity_mismatch`, `unsupported_content`; see [inspection](profiles.md#inspection). |

`nextStep` is sanitized guidance, not an identifier; branch on `id`, `status`
and `code`. Human output reports the same checks. Neither output includes raw
files, credentials, environment values, Session data, generated policy,
unrelated source names/references or private absolute paths. These reads are
observations, not transaction snapshots; later launch conditions can change.

## Effective capability explanation

```sh
acs explain sandbox --profile backend-review
acs explain devin --profile backend-review --json
acs explain codex --profile backend-review --auth work
acs explain run --profile backend-review -- /usr/bin/git status
```

`acs explain` strictly reads the Profile, resolves selected Skills, captures
selected instruction files by exact source/path identity and validates a generic
command when requested. It creates no Session, reads no credential value,
queries no authentication provider, writes no generated configuration and starts
no target/user command. Project-local files are not enumerated.

`--check-native-readiness` opts into bounded platform/backend observation. On
macOS it may run the fixed system Seatbelt readiness helper. A pass establishes
only macOS 26 Apple Silicon and the fixed backend check at that moment.
Versions, authentication, materialization, generated policy, target preflights,
network enforcement and cleanup remain unchecked. Linux and cross-compilation
are not native support evidence.

### Facts and JSON

`--json` emits deterministic format 1 with `requested`, `targetAdded`,
`effective` and `unsupported` arrays. Each fact has a stable ID, kind, typed
value, reason and source object. Effective facts include workspace/private
Session access, common/projected Skills and instructions, process, system-read,
metadata, sysctl, exact Mach-service, terminal/device, environment and coarse
network authority. Codex facts include fixed generated configuration and state
that its full-permission/no-approval settings remain subordinate to ACS.

Local-IP grants permit socket binding only, not `listen`, inbound service
authority or a destination allowlist. Outbound IP and macOS DNS remain coarse.

Executable selections are requested logical facts. A workspace-relative entry
already covered by workspace read is marked
`stored_v3_intent_covered_by_workspace_read`, without a redundant effective
grant. Fixed-search/local selections add effective visibility facts without
passive host lookup; local absolute values are omitted.
`runtime.executable-visibility` records the intrinsic readable runtime;
`unsupported.exclusive-execution-filtering` states that visibility is additive
and non-exclusive, not a command allowlist.

MCP requested facts contain transport, server ID, executable-entry ID, ordered
argv-reference kinds/IDs, input/environment entry IDs and disabled-tool names.
These references affect `authorityDigest`, while local paths, argument values,
environment source names and values do not. Devin/Codex target-added facts name
the registered projection their selected recipe would compile. They do not
prove effective MCP enforcement, server startup, disabled-tool removal,
exclusion of every ambient source or a boundary around children. Generic
`acs run` preserves intent without projecting or starting a server.

Public facts intentionally include Skill/instruction identities and environment
destinations, scope, source/provider class, required state and classification.
They omit environment source names, secret references and values; canonical
source/workspace/executable/runtime/Session paths; argument values; auth
references; credentials; project files; raw native policy; and backend/target
output.

Each unknown inactive v3 overlay yields one sanitized `inactive_overlay_unknown`
limitation. Its key/payload are omitted and it adds no plan fact or digest input.
Missing or unsupported selected overlays fail closed. Legacy v1/v2 remains
Devin-bound with writable workspace and legacy Skill placement; explanation
never migrates or rewrites it.

### Digest meaning

`authorityDigest` is SHA-256 over a versioned length-prefixed canonical encoding
of complete semantic ACS authority and registered recipe requirements, not JSON
or prose. Inputs include:

- Workspace mode, exact Skill/instruction identities, recipe/overlay/projection,
  registered requirement IDs, generated configuration and inheritance.
- Environment-name policy, Session/process/terminal/device/system/Mach/sysctl
  grants and coarse network mode.
- Path IDs, access/type/reference class and workspace-relative logical paths.
- Executable IDs, reference class, fixed-search names and workspace-relative
  logical paths.
- Environment IDs, destinations, scope, source/provider class, required state
  and classification, plus the MCP references described above.

Machine-local bindings are excluded: Profile name/revision, canonical paths,
file contents, local absolute path/executable bindings, argument values, auth
references/provider state, concrete project files, environment source names/
references/values and host readiness. Equal digests do not imply file-level
execution-plan equality, readiness, authorization or native enforcement. The
public digest is not a secret-hiding mechanism.

Execution commands accept optional `--expect-authority-digest sha256:...`.
ACS freshly loads/resolves the plan and returns `authority_plan_changed` before
provider, Session or process side effects on mismatch. A match skips no checks:
generic commands retain executable identity checks; fixed targets retain
platform/backend/path/runtime checks; Codex retains named-resource and exact
version checks; Devin retains contained Skill/authentication preflights. Fresh
argv, auth reference, credential, project file or other excluded binding can
legitimately differ without changing the digest.

JSON check status is `pass`, `fail` or `unchecked`. Exit 0 means a complete
semantic plan was produced. A failed requested readiness observation or a
structural/source/overlay/command failure exits 1. Unchecked properties do not
prevent success. Check the requested statuses before treating a plan as ready to
launch.

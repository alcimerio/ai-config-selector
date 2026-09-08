# Explain effective Profile capabilities

Use `acs explain` to inspect the semantic authority and registered recipe a
fresh execution would use:

```sh
acs explain sandbox --profile backend-review
acs explain devin --profile backend-review --json
acs explain codex --profile backend-review --auth work
acs explain run --profile backend-review -- /usr/bin/git status
```

The command strictly reads the stored Profile, resolves only selected Skill
sources by exact `source` plus `relativePath` identity, and validates a generic
command when requested. It creates no Session, reads no credential value,
queries no authentication provider, writes no generated configuration, and
starts no target or user command. Project-local files are not enumerated.

`--check-native-readiness` opts into the existing bounded platform/backend
observation. On macOS it may run the fixed system Seatbelt readiness helper. A
pass means only that macOS 26 on Apple Silicon and the fixed backend check
passed at that moment. Executable versions, authentication, materialization,
generated policy, target preflights, network enforcement, and cleanup remain
unchecked. Linux and cross-compilation are not native support evidence.

## Facts and JSON

`--json` emits deterministic format 1 with `requested`, `targetAdded`,
`effective`, and `unsupported` fact arrays. Each fact has a stable ID, kind,
typed value, reason, and source object. The effective list includes workspace
read/write, private Session access, selected common and projected Skills,
process, system-read, metadata, sysctl, exact Mach-service, terminal/device,
environment, and coarse network authority. Codex facts include the fixed
generated configuration and state explicitly that target full-permission and
no-approval settings remain subordinate to ACS containment.

The local-IP network grant permits socket binding only; it does not grant
`listen`, inbound service authority, or a destination allowlist. Outbound IP
and the macOS DNS resolver remain coarse grants.

Selected Skill logical identities are intentionally public. Canonical source,
workspace, executable, runtime and Session paths; argument and environment
values; auth references; credentials; project files; raw native policy; and
backend/target output are omitted.

Each unknown inactive version-3 overlay produces one sanitized
`inactive_overlay_unknown` limitation. Its key and payload remain omitted, and
it contributes no plan fact or digest input. Missing or unsupported selected
overlays fail closed. Legacy v1/v2 Profiles remain Devin-bound,
writable-workspace compatible, and use legacy Skill placement; explanation
never migrates or rewrites them.

## Digest meaning

`authorityDigest` is SHA-256 over a versioned length-prefixed canonical encoding
of the plan's complete semantic ACS authority and registered recipe
requirements. It is not a hash of JSON or human prose. Workspace mode, exact
Skill identities, recipe/overlay/projection, registered requirement IDs,
generated configuration, inheritance, environment-name policy, Session/process/
terminal/device/system/Mach/sysctl grants, and coarse network mode affect it.
Explicit path IDs, access/type/reference class, and workspace-relative logical
paths also affect it. Local absolute path values do not.

Machine-local bindings are deliberately excluded: Profile name/revision,
canonical paths and file contents, argument values, auth references/provider
state, concrete project files, environment values, and host readiness. Equal
digests therefore do not claim file-level execution-plan equality, readiness,
authorization, or native enforcement, and the public digest is not a
secret-hiding mechanism.

The matching execution commands accept optional
`--expect-authority-digest sha256:...`. ACS freshly loads and resolves the plan
and fails with `authority_plan_changed` before provider, Session, or process
side effects if the semantic digest differs. A match does not skip existing
validation. Generic commands retain their existing executable identity checks;
fixed targets retain platform/backend/path/runtime checks; Codex still checks
the named resource and exact target version; Devin still performs its contained
Skill and authentication preflights. Fresh argv, auth reference, credential,
project file, or other excluded binding may legitimately differ without a
semantic digest change.

The JSON check status is `pass`, `fail`, or `unchecked`. Exit 0 means a complete
semantic plan was produced. A requested readiness observation that fails, or a
structural/source/overlay/command failure, exits 1. Unchecked default evidence
does not prevent explanation success and must not be read as readiness.

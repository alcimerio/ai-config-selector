# Create and manage Profiles

[Documentation index](../README.md)

Profiles are machine-local JSON documents in `~/.acs/profiles`. Use the
interactive builder for guided selection, or an explicit JSON file for
noninteractive creation. These are alternative creation methods; each new name
must be absent:

```sh
acs devin create-profile --name backend-review
acs codex create-profile --name codex-review --auth work
acs profile create --file profile.json --dry-run
acs profile create --file profile.json
```

Inspect and validate stored Profiles with:

```sh
acs profile list
acs profile show backend-review --json
acs profile validate backend-review
```

The [common format](../reference/common-profile-format.md) defines schema versions, grants,
and migration. Inspection reports stored structure; [validation and
explanation](diagnostics.md) report selected-source availability and effective
authority separately. None of these observations alone proves launch readiness.

## Declarative creation

`acs profile create --file FILE [--dry-run]` accepts one explicit JSON file whose
document supplies the Profile name. Standard input and implicit file selection
are unsupported. Creation accepts only the supported version-3 representation:
common `skills`, optional `instructions`, `workspace`, `paths`, `executables`,
`environment`, reference-only `mcp`, and supported version-1 `devin` and `codex`
overlays. [MCP references](mcp-profiles.md) must bind to selected executable,
path and environment entries. Future envelopes, legacy v1/v2 input, duplicate
keys, unknown fields or capabilities, unsupported overlays, invalid references,
and representations that cannot be preserved losslessly are rejected.

The input must be a regular file no larger than 1 MiB. ACS opens it nonblocking,
validates the opened descriptor and reads it once. FIFOs, devices and directories
are rejected without waiting; symlinks to regular files are supported. Replacing
the pathname after open does not change the captured candidate. The descriptor
pins identity, not an atomic snapshot against in-place writes; candidate bytes
become immutable after the read completes. ACS never changes input bytes or mode.

Creation validates logical environment bindings without reading provider values,
and [instruction references](../reference/common-profile-format.md#instruction-bundles)
without opening instruction files. Omitted instructions remain compatible;
a present capability has a strict version and reference array. Missing Skill
material and absent named Codex authentication are not structural errors. Exact
Skill source/path identities and opaque `authRef` values are preserved without
discovery, display-name rebinding or repair. Creation requires no TTY, target
executable, provider access, native probe, Session or process.

`--dry-run` prints deterministic canonical JSON, including normalized field
order, indentation, final newline and supported defaults, and identifies
unchecked availability/runtime properties. It passively checks destination
absence but creates no directory, lock, journal, Session, credential or other
durable file.

Without `--dry-run`, invocation authorizes publication without terminal
confirmation. ACS recovers under the repository transaction lock and uses the
builder's conditional no-overwrite creation transaction, with the captured bytes
rather than rereading the input. An occupied destination, concurrent winner,
invalid input or cancellation observed before the transaction decision cannot
replace a Profile. Cancellation after the decision begins does not undo a
committed creation. See [outcomes and recovery](#uncertain-outcomes-and-recovery)
before retrying an uncertain result.

## Inspection

`acs profile list [--json]` enumerates direct `.json` entries;
`acs profile show NAME [--json]` inspects one Profile even if selected Skills
have disappeared. `show` and `validate` accept exactly one name before or after
`--json`; `list` accepts none. Flags occur once. Extra operands, unknown options,
attached values (`=`), `--`, target pass-through and sandbox bypass are rejected.
Use `acs help profile` or each command's `--help` for contextual usage.

Human output reports the number of stored Skills, Instructions, path grants,
executables, environment entries and MCP servers. Workspace access is a scalar
setting, shown as configured with its access mode above. Counts do not resolve
references or establish runtime access; use
[`acs explain`](diagnostics.md#effective-capability-explanation) for effective
capabilities. Private path, executable, environment and MCP selection details
remain omitted from inspection output.

Inspection reads persisted structure only. It does not check source existence,
authentication, installed targets or runtime readiness; resolve references;
normalize or migrate files; create directories or Sessions; recover quarantine;
change permissions; or access a terminal. Use `acs profile validate NAME` for
selected Skill resolution and `acs doctor` for passive host prerequisites.

A missing store is an empty successful list. Entries are filename-ordered;
non-`.json` files (including `.profile-*.tmp`) are ignored and preserved. Invalid
entries do not hide valid siblings. Store-directory symlinks and non-directory
components below the user home are rejected. Entry opens do not follow symlinks
or block on FIFOs; only regular files up to 1 MiB are read. Directory descriptors
pin traversal against replacement races. Reads are not a transaction snapshot:
concurrent removal yields a per-entry missing diagnostic and concurrent changes
can yield invalid structure. No cleanup is performed.

### Inspection JSON format 1

Every syntactically valid `--json` invocation writes exactly one compact,
newline-terminated object to stdout, without prose, color or stderr output.
Help remains human text; syntax errors exit 1 with contextual stderr usage.
The output version is independent of stored Profile schemas. For example,
`acs profile show legacy --json` can return a valid version-1 Profile:

```json
{"formatVersion":1,"operation":"show","storage":"present","entries":[{"file":"legacy.json","name":"legacy","status":"valid","storedVersion":1,"target":"devin","categories":[{"id":"skills","schemaVersion":null,"selection":[{"source":"shared-agents","relativePath":"review"}]}],"overlays":[],"workspaceAccess":null,"diagnostic":null}],"diagnostic":null,"checks":{"sources":"unchecked","auth":"unchecked","runtime":"unchecked"}}
```

Every response has these stable fields and types:

- `formatVersion`: integer `1`; `operation`: `list` or `show`.
- `storage`: `present`, `missing` or `unavailable`. Invalid requested names use
  `unavailable` without accessing storage or discovering HOME.
- `entries`: array, never null. List orders by filename; show returns one entry,
  or an empty array on fatal storage errors.
- `diagnostic`: null or `{ "code": string, "message": string }` for fatal
  storage errors. Messages are fixed safe text; branch on codes.
- `checks`: `sources`, `auth` and `runtime` strings, all `unchecked`.

Each entry always contains:

- `file`: ASCII-escaped basename, or null for an invalid requested name.
  Backslashes and non-ASCII/control bytes use Go string escapes without outer
  quotes; `name` is the validated filename stem or null for an invalid name.
- `status`: `valid`, `invalid`, `unsupported`, `missing` or `unreadable`;
  `storedVersion`: integer or null when not safely decoded.
- `target`: `devin` for valid legacy entries, `common` for valid v3, otherwise
  null; `workspaceAccess`: `read-only` or `read-write` for valid v3, otherwise null.
- `categories` and `overlays`: arrays; `diagnostic`: null for a valid entry,
  otherwise the diagnostic object. Invalid/unsupported categories are empty;
  corrupt or unknown payloads are never echoed.

Categories have `id` and `schemaVersion` (stored integer, or null for version-1
legacy Skills). Select by ID, not array order. Nonempty Skills add `selection`;
nonempty Instructions add `instructions`. Both hold references with exactly
`source` and `relativePath` strings. Empty arrays and other category selection
details are omitted. Skills sort by source then relativePath. Overlays sort by
ID and contain `id`, `version` and `support` (`supported`, `unsupported` or
`inactive-unknown`); inspection never selects one for execution.

Supported structures are Devin envelopes 1 and 2 and common envelope 3, with
independently versioned Skills, Instructions, workspace, paths, executables,
environment, MCP and explicit overlays. Version 2 may have an empty categories
object. Environment inspection checks logical shape without source/provider
access or exposing source names, secret references or values. Unknown inactive
overlays are reported without execution. Valid means supported structure, not
executable or ready.

Stored Skill aliases `devin-config` and `shared-agents` and safe relative
spellings remain unnormalized. Absolute, empty, NUL-containing or escaping paths
and duplicate normalized references are invalid. Unknown fields, category IDs,
targets, source aliases and unsupported versions are unsupported, never silently
discarded. Missing fields, wrong types, duplicate keys, malformed references and
filename/body mismatch are invalid. Unpaired JSON UTF-16 surrogate escapes are
invalid; valid supplementary pairs, literal U+FFFD and escaped literal backslash-u
spellings are preserved. JSON escapes controls; human output escapes non-ASCII
and terminal controls. Private absolute paths and arbitrary decoder errors are
never printed.

| Diagnostic code | Meaning |
| --- | --- |
| `storage_unavailable` | Store cannot be safely opened or enumerated (fatal). |
| `invalid_name` | Requested name or filename stem violates name rules. |
| `missing` | Entry is absent or disappeared during listing. |
| `unreadable` | Regular entry cannot be opened/read. |
| `non_regular` | Entry is a symlink, directory, FIFO or other non-regular object. |
| `too_large` | Entry exceeds 1 MiB. |
| `invalid_structure` | Malformed JSON, duplicate keys, required field/type or reference violation. |
| `identity_mismatch` | Persisted name differs from filename stem. |
| `unsupported_content` | Unknown field, target, category, source or unsupported version. |

List exits 0 after complete enumeration, including empty stores and invalid
siblings; fatal storage errors exit 1. Show exits 0 only for a valid entry and
1 for all other results.

## Mutations

```sh
acs profile edit backend-review
acs profile clone backend-review --name frontend-review
acs profile rename backend-review --name service-review
acs profile delete service-review
acs profile delete service-review --confirm service-review
```

After command words, one source `NAME` and separate-token flags may appear in
either order, for example `acs profile clone --name new old`. Names contain 1–64
ASCII letters, digits, dots, underscores or hyphens and begin with a letter or
digit. Clone/rename destinations must be absent and differ from the source by
more than ASCII letter case; case-only renames are refused. Unknown, duplicate,
missing or attached flags (`--name=new`), extra operands, `--`, `--yes`, force,
overwrite and pass-through are rejected. Help and malformed requests do not
inspect HOME, cwd, terminal capabilities, storage or runtime dependencies.

### Editing and selection repair

Edit and clone open the Profile Builder with saved selections; clone uses the
new name. Both require interactive stdin/stdout, but no installed client,
authentication, Session, active platform probe or launch plan.

Open Skills with Enter; navigate with Up/Down, toggle with Space/Enter, search
with `/`, and return with Left/Esc. Esc clears a search filter first. `R` refreshes
focused Skills. Failed discovery offers retry, back or `E` to edit saved
selections. Selections survive navigation, filtering, resize, failed discovery
and refresh. Dirty drafts require confirmation before discard.

Rows combine saved and discovered choices by exact **source plus relative path**,
never display name. Missing or ambiguous saved identities stay visible and
selected until explicitly removed. Replace one by deselecting it and selecting
the intended identity. Missing roots/manifests can establish absence; failed
reads leave that source unavailable/unchecked, while readable sources still
offer choices. Availability can change and is not a launch-readiness promise.

### Preview and commit

Choose Preview Edit or Preview Clone; rename immediately shows an old/new-name
and representation preview. Scroll with Up/Down, PgUp/PgDn or End and reach the
final page before confirming. Preview lists added, removed and retained
selections and exact canonical JSON. Retained unresolved selections need a
separate `A` warning acknowledgement before Y/Enter commits. Saving them does
not install Skills or establish authentication/runtime readiness.

Preview discloses v1 → v2 conversion (`skillReferences` to schema-1
`categories.skills`), missing defaults, sorting, field order, indentation and
final newline, or supported v2 canonicalization. Even unchanged legacy
selections require preview. Ordinary legacy mutations remain canonical v2 with
writable-workspace authority and old placement. Explicit
[`acs profile migrate NAME`](../reference/common-profile-format.md#explicit-migration-and-outcomes)
adopts v3 through the same revision-bound Replace transaction and previews
retained/reduced authority and common/Devin projection paths.

Eligibility comes from bounded exact bytes captured with their revision and
filename identity, not permissive codec normalization. Unknown fields or inactive
v3 overlays, future content, unsupported targets/categories/sources, duplicate
keys, ambiguous structure, unsafe references and identity mismatch refuse
rewriting without changing bytes, modes or the Profile tree. Commit owns exactly
the previewed bytes and expected revisions, not later mutable editor state.

### Conflicts and cancellation

A conditional commit conflict preserves newer stored data and the draft. There
is no force retry. `L` requests reload; `Y` discards the draft and reads a strict
snapshot, while `N` keeps it. Retry requires fresh preview and confirmation, as
do ordinary save failures. Occupied destinations, including malformed entries
and native filesystem aliases, are never overwritten.

Esc returns from preview; Ctrl+C/Ctrl+D cancel before commit with dirty-draft
discard confirmation (exit 130). EOF, confirmation mismatch, pre-commit
cancellation and stale revisions cannot authorize deletion. Terminal state is
restored on completion, cancellation, signals and errors. During an active save,
ACS waits for the repository outcome; cancellation or later cleanup errors do
not undo a commit. After a handled failure and reload, cancelling does not
report the old failure again. Refresh completion preserves pending discard
confirmation; declining returns to the refreshed editor or discovery error.

### Deletion authority

Interactive delete shows content status and requires the exact name then Enter;
a mismatch clears input, and Y/Enter alone is insufficient. Noninteractive
`--confirm NAME` must exactly match and still deletes conditionally against a
bounded snapshot revision.

A safely readable private regular document may be deleted when corrupt or
unsupported; preview warns and does not decode/re-encode it. Unsafe paths,
nonregular entries, unexplained hard links and repository boundary violations
are refused. Only the confirmed stored Profile is deleted; other Profiles,
authentication identities and active Session copies remain. There is no
automatic undo.

## Uncertain outcomes and recovery

Creation and mutations use the [revisioned repository](../development/architecture.md#profile-repository-transactions).
Apply owns recovery under the same stationary lock after authorization;
preparation and cancellation create no locks or journals. There is no second
publication or recovery engine.

A committed-with-error result exits nonzero and reports that publication
committed but cleanup or reporting failed. If the transaction settled and only
output/terminal reporting failed, inspect the committed Profile; repository
recovery is unnecessary. Cleanup failure can require recovery independently of
commitment. `Unknown` means publication may have occurred: do not blindly retry.
Neither uncertainty nor a known commit becomes ordinary cancellation after
Ctrl+C or terminal failure.

For recovery-required or Unknown results, follow the printed recovery command,
for example:

```sh
acs devin create-profile --name backend-review
```

That entry point recovers before its duplicate check. Cancel the builder if it
opens, then inspect with `acs profile list` and `acs profile show NAME` before
deciding what to do. Recovery can finish the earlier operation; it is not
rollback. Do not delete transaction artifacts or bypass a live lock. The
repository contract describes revisions, writer limits, two-name rename
visibility and native filesystem durability.

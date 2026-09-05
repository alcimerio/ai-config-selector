# Inspect stored Profiles

`acs profile list [--json]` lists direct `.json` entries in `~/.acs/profiles`.
`acs profile show NAME [--json]` inspects one saved Profile, even when its selected
Skills have been removed. `acs profile show --json NAME` is also accepted.
`show` and `validate` accept one name operand; other existing commands still accept no operands.
Flags occur once. Extra operands, unknown options, `=`, `--`, target pass-through,
and sandbox bypass are rejected. Use `acs help profile`, `acs profile list --help`,
or `acs profile show --help` for contextual help.

Inspection reads persisted structure only. It does not check source existence,
authentication, installed targets, or launch readiness. It does not resolve
references, normalize or migrate files, create directories or Sessions, recover
quarantine, change permissions, or access a terminal. Launch and authentication
contracts are unchanged. For selected-source resolution, use
`acs profile validate NAME`; for passive host prerequisites, use `acs doctor`.
See the [passive diagnostics contract](passive-diagnostics.md). To create a Profile, use
`acs devin create-profile --name NAME` in an interactive terminal.

A missing store is an empty successful list. Entries are ordered by filename;
non-`.json` files (including `.profile-*.tmp`) are ignored and preserved. Invalid
entries do not hide valid siblings. Store-directory symlinks and non-directory
components below the user home are rejected. Entry opens do not follow symlinks
and cannot block on FIFOs; only regular files are read, up to 1 MiB per entry.
Directory descriptors pin traversal against replacement races. Reads are not a
transactional snapshot: concurrent removal is a per-entry missing diagnostic,
and concurrent changes may produce invalid structure. No cleanup is performed.

## JSON output format 1

This is a new output contract, independent of stored Profile schema versions.
Each `--json` invocation that passes syntax validation writes exactly one compact,
newline-terminated JSON object to stdout, without prose, color, or stderr output.
Help remains human text; syntax errors retain exit 1 and contextual stderr usage.

Example `acs profile show legacy --json` for a valid stored version-1 Profile:

```json
{"formatVersion":1,"operation":"show","storage":"present","entries":[{"file":"legacy.json","name":"legacy","status":"valid","storedVersion":1,"target":"devin","categories":[{"id":"skills","schemaVersion":null,"selection":[{"source":"shared-agents","relativePath":"review"}]}],"diagnostic":null}],"diagnostic":null,"checks":{"sources":"unchecked","auth":"unchecked","runtime":"unchecked"}}
```

Every object has these fields, with stable types:

- `formatVersion`: integer `1`; `operation`: `list` or `show`.
- `storage`: `present`, `missing`, or `unavailable` (including invalid requested
  names, for which storage is not accessed).
- `entries`: array, never null. List orders entries by stored filename. Show
  returns one entry, except fatal storage errors which return an empty array.
- `diagnostic`: null, or `{ "code": string, "message": string }` for fatal
  storage errors. Messages are fixed safe text; consumers should branch on codes.
- `checks`: object whose `sources`, `auth`, and `runtime` strings are `unchecked`.

Each entry always has `file` (ASCII-escaped basename, or null for an invalid
requested name; backslashes and non-ASCII/control bytes use Go string escapes,
without surrounding quotes), `name` (validated filename stem, or null for an invalid
name), `status` (`valid`, `invalid`, `unsupported`, `missing`, or `unreadable`),
`storedVersion` (integer or null when not safely decoded), `target` (`devin` for
valid entries, otherwise null), `categories` (array), and `diagnostic` (null for
valid entries, otherwise the diagnostic object). No corrupt or unknown payload
is echoed. Invalid/unsupported entries have empty categories. A valid entry
means supported persisted structure only; it does **not** mean executable.

Categories are ordered by ID; each has `id`, `schemaVersion` (stored integer;
null for version-1 legacy Skills, which had no category envelope), and `selection`
(array). Skills references have exactly `source` and `relativePath` strings and
are ordered by source then relativePath. Stored aliases `devin-config` and
`shared-agents` and safe relative spellings are preserved, without normalization.
Absolute, empty, NUL-containing, or escaping paths and duplicate normalized
references are invalid. JSON escapes controls; human output escapes non-ASCII
and terminal controls. Private absolute paths and arbitrary decoder errors are
never printed.

Supported structures are Devin Profile envelopes 1 and 2 and Skills category
schema 1. Version 2 may have an empty categories object. Unknown fields, category
IDs, targets, source aliases, and unsupported versions are explicitly unsupported;
missing fields, wrong types, duplicate JSON keys, filename/body mismatch, and
malformed references are invalid. Unpaired JSON UTF-16 surrogate escapes are
invalid; valid supplementary pairs, literal U+FFFD, and escaped literal backslash-u
spellings are preserved. Invalid show names are rejected before home discovery,
so their diagnostic does not depend on HOME. Unknown fields are not silently discarded.

Stable diagnostic codes:

| Code | Meaning |
| --- | --- |
| `storage_unavailable` | Store cannot be safely opened or enumerated (fatal). |
| `invalid_name` | Requested name or filename stem violates Profile name rules. |
| `missing` | Requested entry is absent or disappeared while listing. |
| `unreadable` | Regular entry cannot be opened/read. |
| `non_regular` | Entry is a symlink, directory, FIFO, or other non-regular object. |
| `too_large` | Entry exceeds 1 MiB. |
| `invalid_structure` | Malformed JSON, duplicate keys, required field/type or reference violation. |
| `identity_mismatch` | Persisted name differs from filename stem. |
| `unsupported_content` | Unknown field, target, category, source, or unsupported version. |

List exits 0 when enumeration completes, including empty stores and mixed invalid
entries; a fatal storage error exits 1. Show exits 0 only for a valid entry and
1 for missing, invalid, unsupported, unreadable, or fatal storage results.

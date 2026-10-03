# Recoverable local Profile history

[Documentation index](../README.md)

ACS records private local history for each committed Profile creation, edit,
clone, rename, deletion, import, migration and restore. Use it to recover
supported configuration state. Use [portable exchange](portable-profile-exchange.md)
to transfer selections; history is not a portable backup.

## Commands

```sh
acs profile history backend-review --limit 20
acs profile history --lineage ln_0123456789abcdef0123456789abcdef --json
acs profile diff backend-review --revision ev_0123456789abcdef0123456789abcdef
acs profile diff --lineage ln_0123456789abcdef0123456789abcdef \
  --revision ev_0123456789abcdef0123456789abcdef \
  --to ev_fedcba9876543210fedcba9876543210 --json
acs profile restore backend-review \
  --revision ev_0123456789abcdef0123456789abcdef --dry-run --json
acs profile restore --lineage ln_0123456789abcdef0123456789abcdef \
  --revision ev_0123456789abcdef0123456789abcdef \
  --as recovered-review --bindings local-bindings.json --dry-run --json
acs profile restore backend-review \
  --revision ev_0123456789abcdef0123456789abcdef \
  --expect hg_DIGEST_FROM_PREVIEW --confirm backend-review
```

Use the actual `eventId` and `lineageId` from `history --json` in these examples;
the displayed IDs and `hg_DIGEST_FROM_PREVIEW` are placeholders.

Select history with either a live `NAME` or an opaque `--lineage ID`. Event IDs
use `ev_` plus 32 lowercase hexadecimal digits; lineage IDs use `ln_` plus 32
lowercase hexadecimal digits. These are identifiers, not paths or content hashes.

A lineage tracks one Profile through mutations. Rename preserves it. Deletion
leaves a tombstone that you can select by lineage ID. Reusing a deleted name
creates a new lineage, and a live name resolves only its current lineage.

An existing Profile enters history on its first successful mutation. Until
then, its history is empty. History, diff, restore dry-run and prune dry-run
are passive. They do not create or repair storage, take a repository lock,
access a provider or Keychain, probe executables, create Sessions or start targets.

## Restore

Each event records the state produced by a successful operation. Restore
selects that supported state. First adoption also records a protected
predecessor, retaining the bytes displaced by the first mutation. A deletion
tombstone selects the last live snapshot for recovery and reports its resulting
state as deleted.

Restore decodes the selected snapshot with the current Profile codec, changes
the destination logical name and canonicalizes the document. It preserves
current machine-local bindings from a valid live destination. A corrupt or
unsupported destination is rejected, rather than treated as absent.

If the destination is absent or cannot supply every required binding, pass
`--bindings FILE` with the local binding document accepted by Profile import.
Current choices take precedence; the file supplies missing choices. Binding
version 1 supports source and authentication references, version 2 adds paths
and executables, and version 3 adds environment references.

Restore never reuses machine-local path, executable, or secret-environment
reference values solely because they occurred in an old private snapshot. A live
destination supplies a local executable binding only when entry ID and reference
kind still match; otherwise an explicit current exchange binding is required. A
secret environment reference is preserved only from a live destination whose
entry ID, destination, scope, required/classification fields, source kind, and
provider still match. Non-secret host names remain portable logical intent. It
never restores credential values, Keychain items, external Skill files, target
authentication state, Sessions, provider state, or generated policies.
Unsupported or corrupt old schemas and unresolved, invalid or conflicting
binding decisions fail before mutation. Reading and validating `--bindings` is
local and provider-free; dry-run still does not access a provider or Keychain.

A binding file uses the existing strict Profile-import shape. Version 1 remains
compatible when only source/authentication bindings are required; version 2 adds
path and executable binding maps; version 3 adds the environment binding map.
The required keys depend on the selected supported intent; omitted, extra,
duplicate, unsafe, or unsupported choices fail closed:

```json
{
  "bindingVersion": 3,
  "sources": {"source-1": "shared-agents"},
  "authentications": {"authentication-1": "work"},
  "paths": {},
  "executables": {"executable-1": "/Users/example/bin/tool"},
  "environment": {"environment-1": "ACS_SERVICE_TOKEN"}
}
```

Dry-run reports the destination condition, sanitized changes from its current
state to the canonical candidate, and an `hg_` digest. Name changes are explicit
facts. Skill changes remain sorted set additions and removals.

The digest binds the lineage, event, destination name, current repository
revision or absence, intended document and validated bindings. It excludes time
and the future random event ID. Apply rereads any binding file, requires the
same digest and `--confirm NAME`, and rechecks under the repository mutation
lock. It never force-overwrites another lineage.

`--as NAME` requires an absent destination. For a deleted lineage, restore
continues that lineage under the new live name. For a renamed lineage whose
Profile remains live elsewhere, restore preserves the live Profile and creates
a conditional clone. The destination gets a distinct derived lineage, with
the selected lineage recorded as its source. Preview binds the live source
revision; apply revalidates the source and absent destination under the lock.

A derived restore preserves the source name-to-lineage binding; deleting the
source later appends its tombstone to that original lineage. Recovery preserves
this distinction. A committed restore reports resulting `eventId` and
`lineageId` separately from `selectedEventId` and `sourceLineageId`; the source
and result lineage IDs differ for a renamed-live `--as` restore.

## Pins, retention, and pruning

```sh
acs profile history pin --lineage ln_ID --revision ev_ID
acs profile history unpin --lineage ln_ID --revision ev_ID --confirm ev_ID
acs profile history prune --lineage ln_ID --keep 50 --dry-run
acs profile history prune --lineage ln_ID --keep 50 \
  --expect hg_DIGEST_FROM_PREVIEW --confirm ln_ID
```

ACS retains the latest 100 ordinary unpinned events plus pinned and
recovery-protected entries. Each lineage is limited to 256 committed events
and 32 MiB of logical snapshot bytes. Each snapshot has the 1 MiB Profile
document limit. If protected data leaves no safe capacity, admission fails
before the Profile transaction decision.

Prune keeps 1 through 100 ordinary events, with a default of 100. Preview
reports a sanitized candidate count and digest. Apply requires that digest
and exact lineage confirmation; candidate IDs and keep count are digest-bound.
Pins and the last recoverable predecessor are retained.

Pin and prune metadata use versioned, locked recovery. Repository recovery
completes interrupted maintenance, and repeated recovery is idempotent.

## Privacy, corruption, and outcomes

History lives under `profiles/history` in mode-0700 directories. Event
records, snapshots, name bindings and maintenance journals are owned,
mode-0600, regular single-link files opened through descriptor-relative
no-follow operations. Snapshots can retain old local references and must
remain private.

Text and JSON expose bounded semantic descriptors and redacted binding status.
They omit stored bytes, credentials, private paths, external asset contents,
argv and generated sandbox policy.

JSON emits one schema-version-1 object. History lists use an `events` array,
which is empty rather than null when no events exist. Public output is capped
at 1 MiB. Grammar errors exit 2; conflicts, missing or corrupt state, quota
failures and recovery-required results exit 1; success exits 0.

Corruption blocks the affected lineage without disabling mutations of unrelated
Profiles. Use ordinary repository recovery rather than editing private history
files or deleting journals. Preserve evidence when recovery reports an unsafe
or unknown outcome.

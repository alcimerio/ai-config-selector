# Recoverable local Profile history

Current development source records private local history for every committed Profile create, edit, clone, rename, delete, import, migration, and restore. History is recovery state, not a portable backup or export format.

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

Exactly one live `NAME` or opaque `--lineage ID` selects history. Event IDs use fixed lowercase `ev_` plus 32 hexadecimal digits; lineage IDs use `ln_` plus 32 hexadecimal digits. They are identifiers, never paths or repository content hashes. A live name resolves only its current lineage. Rename preserves a lineage; deletion leaves a selectable tombstone addressable by lineage ID. Reusing a deleted name creates a new lineage.

An existing Profile is adopted only on its first successful mutation. Passive history, diff, restore dry-run, and prune dry-run never create or repair storage, take a repository lock, access a provider or Keychain, probe an executable, create a Session, or start a target. History for an unadopted live Profile is empty.

## Restore

A history event advertises the state produced by its successful operation, and selecting a live event restores that advertised supported state. First adoption records a protected predecessor so the bytes displaced by the first mutation remain selectable. A deletion tombstone selects its last live snapshot for recovery while reporting its resulting state as deleted.

Restore decodes the selected snapshot through the current Profile codec, changes only the destination logical name, canonicalizes it, and preserves current machine-local binding choices where a valid live destination supplies them. If the destination is absent, or its current intent cannot supply every selected binding decision, pass `--bindings FILE` using the same bounded version-1 local binding document accepted by Profile import. Current choices still take precedence when only missing choices need the file. A corrupt or unsupported current destination is rejected; it is never treated as absent and never contributes guessed bindings.

Restore never reuses machine-local binding values solely because they occurred in an old private snapshot. It never restores credential values, Keychain items, external Skill files, target authentication state, Sessions, provider state, or generated policies. Unsupported or corrupt old schemas and unresolved, invalid or conflicting binding decisions fail before mutation. Reading and validating `--bindings` is local and provider-free; dry-run still does not access a provider or Keychain.

A binding file uses the existing strict Profile-import shape. Its exact required
keys depend on the selected supported intent; omitted, extra, duplicate, unsafe,
or unsupported choices fail closed:

```json
{
  "bindingVersion": 1,
  "sources": {"source-1": "shared-agents"},
  "authentications": {"authentication-1": "work"}
}
```

Dry-run reports the destination condition, the actual sanitized semantic change from current destination state to the final canonical candidate, and an `hg_` digest. Profile name changes are explicit semantic facts, and repeated Skill selections remain exact sorted set additions/removals rather than being collapsed to one value. The digest binds the lineage/event, destination name, current repository revision or absence, canonical intended document, and exact validated binding decision; it excludes time and the future random event ID. Apply rereads the binding file when present, requires the same digest and `--confirm NAME`, recompiles and rechecks under the repository mutation boundary, and never force-overwrites another lineage.

`--as NAME` is a no-clobber destination. For a deleted lineage it appends the restore to that lineage under the new live name. For a renamed lineage whose current Profile remains live elsewhere, it preserves that live Profile and performs the restore as a conditional clone: the destination receives a distinct derived lineage whose immutable restore event records the selected lineage as its source relationship. Preview binds the live source revision, and apply revalidates both that source and the absent destination under the repository lock.

A committed restore reports the new `eventId` and resulting `lineageId` separately
from `selectedEventId` and `sourceLineageId`. For an in-line restore the source and
result lineage IDs match. For a renamed-live `--as` restore they differ, making
the derived lineage relationship explicit without claiming that the new event
was appended to the still-live source lineage.

## Pins, retention, and pruning

```sh
acs profile history pin --lineage ln_ID --revision ev_ID
acs profile history unpin --lineage ln_ID --revision ev_ID --confirm ev_ID
acs profile history prune --lineage ln_ID --keep 50 --dry-run
acs profile history prune --lineage ln_ID --keep 50 \
  --expect hg_DIGEST_FROM_PREVIEW --confirm ln_ID
```

ACS retains the latest 100 ordinary unpinned events plus pinned and recovery-protected entries. A lineage has a hard limit of 256 committed events and 32 MiB of logical snapshot bytes; each snapshot remains subject to the 1 MiB Profile document limit. Admission fails before the Profile decision when protected data leaves no safe capacity.

Prune keeps 1 through 100 ordinary events (default 100). Preview lists only a sanitized candidate count and digest. Apply requires the digest and exact lineage confirmation. Candidate IDs and keep count are digest-bound. Mutable pin and prune metadata has its own versioned, locked recovery: interruption is completed on repository recovery and repeated recovery is idempotent. Pins and the last recoverable predecessor are not candidates.

## Privacy, corruption, and outcomes

History lives in the mode-0700 `profiles/history` child. Lineage directories are mode 0700; immutable event records, full snapshots, name bindings, and maintenance journals are owned mode-0600 regular single-link files opened with descriptor-relative no-follow operations. Snapshot bytes can retain old local logical references and are private. Text and JSON expose only bounded semantic descriptors and redacted binding status, never stored bytes, credentials, private filesystem paths, external asset contents, argv, or generated sandbox policy.

JSON emits one schema-version-1 object and history lists use an `events` array that is empty rather than null. Public output is capped at 1 MiB. Grammar errors exit 2; operational conflict, missing, corrupt, quota, and recovery-required results exit 1; success exits 0.

Corruption blocks the affected lineage. A corrupt lineage or maintenance witness does not disable mutation of an unrelated Profile. Do not edit private history files or delete recovery journals manually; use the ordinary repository recovery path and preserve evidence when recovery reports an unsafe or unknown outcome.

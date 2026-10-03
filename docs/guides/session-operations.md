# Durable Session inspection and recovery

[Documentation index](../README.md)

ACS records sanitized lifecycle information for every contained shell, Devin,
Codex, Codex authentication, and explicit command Session. Use the record to
inspect lifecycle state. Recovery also requires an inactive Session lease, its
exact private process generation and the matching native supervisor cleanup
proof.

```sh
acs session list
acs session list --state retryable --json
acs session list --limit 128 --json
acs session list --limit 128 --after ses_abcd234567abcdef234567abcd --json
acs session inspect ses_abcd234567abcdef234567abcd
acs session recover ses_abcd234567abcdef234567abcd
```

Replace the illustrative Session ID with one returned by `acs session list`.
Session IDs are `ses_` followed by exactly 26 lowercase base32 characters.
Valid filters are `active`, `settling`, `retryable`, `unproven`, `removable`,
`removed`, `unknown`, and `corrupt`. Help and grammar failures do not discover
storage. List and inspect are passive: they take no lock, create no files, and
do not access Profiles, targets, providers, Keychain, or the sandbox.

The public JSON contains only the Session ID, coarse target and lifecycle
state, UTC timestamps, record revision, observation quality, and a coarse
recovery action. It never includes a filesystem path or root name, PID, argv,
environment, policy, output, authentication reference, identity, marker,
challenge, credential, or private binding token. A list may report only the
count of safely observed unindexed roots; those roots receive no synthetic ID
or recovery route. A paginated list may include `nextAfter`, an
opaque Session ID to use with the next `--after` request.

Without `--limit`, listing remains complete or fails as a whole if the public
JSON would exceed 1 MiB; it never silently truncates. For larger registries, use
`--limit N` with an integer from 1 to 512. `--after ID` requires `--limit` and a
valid Session ID, and selects record candidates strictly after that ID in
ascending Session ID order. The cursor need not identify a record that still
exists. Preserve the same `--state` filter while paging.

The limit counts record candidates examined, before the state filter is
applied. A filtered page can therefore have no Sessions and still return
`nextAfter`. Continue until `nextAfter` is absent, even after an empty page.
The human output prints a next-page command only when there is a continuation.
Each page reports the global safely observed untracked-root count; do not sum
that count across pages.

Recovery is bounded and non-forcing. A held operation fence reports `busy`; a
live Session lease reports `active`. After ownership is acquired, ACS rereads
the exact private generation and verifies its authenticated cleanup proof.
Codex Sessions must also resolve exactly one typed authentication marker, take
its identity lock, and match the same challenge. Missing, ambiguous, malformed,
changed, or unavailable evidence remains preserved. ACS never kills a process,
infers safety from PID or an unlocked lease, accepts a raw path, or offers a
force/proof override.

Only successful physical removal followed by durable publication reports
`removed`. Removed metadata is retained for 720 hours; a maintenance pass
examines at most 256 record candidates during a later Session allocation and may
delete expired removed metadata, but only after private capability and
root-binding finalization is complete. A durable advisory cursor advances across
allocations and wraps so retained candidates do not permanently block later
records. The cursor never authorizes deletion. Nonexpired metadata and
recoverable evidence are never deleted by maintenance. Pending or unverifiable
finalization evidence is retained for recovery regardless of age. `unproven`,
`unknown`, and `corrupt` evidence has no automatic destructive expiry. Never
delete Session roots, lease files, protection, capabilities, proofs, or Codex
markers by hand.

Completion is restart-safe across partial writes and deletions. If an atomic
rename or unlink became visible before its directory sync failed, a later
recovery re-establishes the durable completion binding before discarding any
remaining private evidence. A visible `removed` record by itself is not a
cleanup override: it must carry the exact private root and challenge binding
published by the successful cleanup sequence.

Each record and private capability is limited to 16 KiB. A list emits at most 1
MiB of public JSON; exceeding that limit fails the whole operation without a
partial list or partial count. Page selection and maintenance keep candidate and
record memory bounded, while streaming the complete directory-name set is still
O(N) work. Counting roots uses direct bindings where available; legacy or
incomplete bindings require another complete record scan per 256-root batch.
These operations bound memory, not total runtime. There is no 4,096-entry
registry ceiling. Recovery lookups stream to the end of the relevant directory
so a later conflicting match still makes the evidence ambiguous; they never
treat the first page as complete proof.

Each passive row is individually consistent, but a list or sequence of pages
is not a globally locked snapshot. Concurrent removals are omitted, and records
inserted at or before the current cursor can be missed until listing restarts.
Later mutations can also change a row's observed state or whether it matches
the requested filter. `active` and `settling` observations are explicitly
unverified because the passive reader does not take the live lease. Revision
fences detect competing writers; they are not an offline rollback detector.

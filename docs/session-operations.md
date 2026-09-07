# Durable Session inspection and recovery

ACS records sanitized lifecycle information for every contained shell, Devin,
Codex, Codex authentication, and explicit command Session. The record is an
operator view, not deletion authority: recovery additionally requires the
inactive Session lease, its exact private process generation, and the native
supervisor cleanup proof for that generation.

```sh
acs session list
acs session list --state retryable --json
acs session inspect ses_abcd234567abcdef234567abcd
acs session recover ses_abcd234567abcdef234567abcd
```

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
or recovery route.

Recovery is bounded and non-forcing. A held operation fence reports `busy`; a
live Session lease reports `active`. After ownership is acquired, ACS rereads
the exact private generation and verifies its authenticated cleanup proof.
Codex Sessions must also resolve exactly one typed authentication marker, take
its identity lock, and match the same challenge. Missing, ambiguous, malformed,
changed, or unavailable evidence remains preserved. ACS never kills a process,
infers safety from PID or an unlocked lease, accepts a raw path, or offers a
force/proof override.

Only successful physical removal followed by durable publication reports
`removed`. Removed metadata is retained for 720 hours; a bounded maintenance
pass may delete it during a later mutating Session operation. `unproven`,
`unknown`, and `corrupt` evidence has no automatic destructive expiry. Never
delete Session roots, lease files, protection, capabilities, proofs, or Codex
markers by hand.

Completion is restart-safe across partial writes and deletions. If an atomic
rename or unlink became visible before its directory sync failed, a later
recovery re-establishes the durable completion binding before discarding any
remaining private evidence. A visible `removed` record by itself is not a
cleanup override: it must carry the exact private root and challenge binding
published by the successful cleanup sequence.

Each record and private capability is limited to 16 KiB. A single operation
scans at most 4096 entries and emits at most 1 MiB of public JSON; exceeding a
limit fails the whole operation without a partial list or partial count.

Each passive row is individually consistent, but a list is not a globally
locked snapshot. `active` and `settling` observations are explicitly
unverified because the passive reader does not take the live lease. Revision
fences detect competing writers; they are not an offline rollback detector.

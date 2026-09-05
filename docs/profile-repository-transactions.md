# Revisioned Profile repository transactions

The development source stores direct `NAME.json` documents through
`internal/profilerepo`. This internal boundary accepts canonical desired bytes;
it has no Profile decoder, category registry, Session dependency, or authentication
provider. Store creation still normalizes and encodes the existing Profile schema
above this boundary. No new Profile schema or edit, rename, delete, migration,
history, updater, or execution command is introduced.

## Calls and conditions

`New(acsHome)` is inert. `Read(ctx, name)` is a passive bounded observation and
returns existence, exact bytes and an opaque `Revision`. `AbsentRevision(name)`
constructs the explicit named absent condition without accessing storage.
The zero revision is invalid. Revisions bind a domain-separated SHA-256 digest
to the exact requested ASCII name, presence and original bytes. No decoder,
normalization, modification time, inode or generation contributes to the revision.
Empty present bytes differ from absence; nil desired bytes mean an empty present
document, never deletion. Formatting changes change a revision. Same-byte
replacement and A-to-B-to-A return to the same current-content condition, as does
absence-to-created-to-deleted. There is no historical ABA detection or tombstone.

`Apply(ctx, request)` supports exactly these request types:

| Request | Conditions checked under the repository lock | Result |
| --- | --- | --- |
| `CreateRequest` | Destination has its named absent revision | Publish supplied bytes without overwrite |
| `ReplaceRequest` | Name has its expected present revision | Replace that document with supplied bytes |
| `CloneRequest` | Source has its expected present revision; destination has its named absent revision | Publish supplied destination bytes; leave source unchanged |
| `RenameRequest` | Same two conditions as clone | Publish supplied destination bytes, synchronize, then remove source and synchronize |
| `DeleteRequest` | Name has its expected present revision | Remove only that named document |

Create, clone and rename never overwrite an occupied destination. A hard-link
publication fails atomically if another process occupies that name, including
with coincidentally equal bytes. Rename can expose both names between its two
namespace operations. It is recoverable coordination, not a two-name atomic
snapshot. Same-name and ASCII case-only clone/rename pairs are rejected on every
volume; other occupied case aliases follow the actual filesystem's exclusive
publication behavior. Embedded document identity is entirely the caller's
responsibility. Recovery neither decodes nor changes supplied bytes. Session
copies and named authentication identities are unaffected by deletion.

Apply copies and bounds desired bytes, acquires ownership, explicitly recovers any
preceding transaction, then rereads this request's conditions under that same
ownership. A recovery failure belongs to the preceding transaction: the new
request remains `NotCommitted` and receives the recovery error. Advisory exclusion
covers cooperating writers using this same lock. Object identity, bytes, modes
and path checks reject observed outside interference; they cannot exclude arbitrary
same-user writers between syscalls or detect every outside ABA rewrite.

## Authority and ownership

The configured ACS home's parent is the trust root, resolved once when opening an
operation. Below that root, ACS home and `profiles` are opened with descriptor-
relative no-follow directory operations. Their pinned identities and the lock's
name/inode binding are rechecked for filesystem operations. Mutation bootstrap
checks parent namespace synchronization, directory modes and directory sync.
Ordinary reads never bootstrap, chmod, lock, clean up, or recover.

The repository has one stationary `.profile-transaction-lock`: an owned, private,
regular, empty, single-link file. Ownership is a nonblocking exclusive `flock`.
A competing mutation or recovery reports `ErrBusy`; timeout and PID metadata are
not ownership evidence. A stopped live holder retains ownership. Process exit
releases kernel ownership; CLOEXEC prevents transferring it through exec. The
lock is never removed, replaced, or reclaimed as cleanup. Do not delete a live
lock to bypass contention.

Directories touched by mutation use mode 0700; documents, staging, journal and
lock files use mode 0600. Existing document entries must already be owned private
regular files. Symlinks, FIFOs, devices, directories and unexplained hard links
are refused. A passive repository read can recognize the deliberate staging link
using decision metadata without acquiring a lock. File descriptors use NOFOLLOW,
NONBLOCK and CLOEXEC. Path replacement never authorizes following a new path out
of the pinned repository. This is confinement and consistency checking, not
cryptographic authentication against the repository owner.

Bounds are independent of Profile decoding: names have 1–64 ASCII characters
using the existing Profile grammar, documents have at most 1 MiB, each metadata
file at most 8192 bytes, each enumerated filename at most 255 bytes, and a recovery
scan at most 4096 repository entries, including unrelated files. There are only
six recognized in-flight artifact leaves plus the permanent lock. Metadata has a
fixed object shape with at most two object levels; unknown keys, versions,
noncanonical encodings, duplicate fields, trailing content, inconsistent object
identities and operation shapes are rejected. Journal data contains validated
names, never filesystem paths. Artifact leaves are derived by the implementation.
Unknown reserved artifact names and case aliases are preserved and block mutation.
Unrelated non-reserved files are preserved.

## Finite recovery protocol

All in-flight leaves use the non-`.json` prefix `.profile-transaction-` and remain
inside `profiles`. One transaction is in flight at a time. Its canonical plan
records format version 1, a random transaction identifier, operation, validated
names, original source identity/hash/length, and staged identity/hash/length.
The plan's metadata format is separate from all document codecs.

1. **Preparation:** create `stage` exclusively, write exact bytes, check full
   write, file sync and close, and sync the directory. Write/sync/close `pending`,
   then rename it to `plan` and sync the directory. Public names are unchanged.
   Delete needs no stage. Recheck observed source/destination state and cancellation.
2. **Decision:** hard-link `plan` to `decision`, then sync the directory. Both
   leaves identify the same complete immutable record. From the beginning of this
   interval, an error may require recovery and cannot be a blind safe retry.
3. **Publication:** create/clone/rename hard-link the staged inode into the absent
   destination. Replace prepares `swap`, rechecks the source, then renames that
   staged link over the matched source. Check namespace sync. Rename and delete
   remove only the matched source, then check another namespace sync. Recovery
   recognizes this transaction's publication by staged inode plus exact bytes,
   size and mode; equal bytes alone are insufficient. Every deliberate staging,
   swap and public link is accounted for during replay.
4. **Terminal receipt:** hard-link `plan` to `complete`, then sync. Recovery also
   synchronizes an observed complete receipt before beginning terminal cleanup.
5. **Cleanup:** validate remaining artifacts and remove pending/swap/stage,
   decision, plan, then complete, with checked synchronization after each removal.
   Complete is last and contains the entire plan. Interrupted terminal cleanup
   does not require an already deleted stage or plan leaf and never restores an
   old public document. Repeated recovery converges to no in-flight artifacts.

Before a decision, recovery aborts private preparation. A partial stage or an
incomplete current-version pending prefix is recognized without requiring a
complete plan; complete malformed or future-version pending records are preserved.
Abort cleanup can itself be interrupted after deleting the stage. After a decision,
recovery rolls forward or preserves evidence and reports interference/uncertainty.
There is no post-commit backup restoration or user-facing undo. Unknown future or
externally inconsistent states remain untouched and may block mutation.

## Outcomes, cancellation and durability

The returned `Outcome.State` is `NotCommitted`, `Committed`, or `Unknown`.
`RecoveryRequired` is separate from that state. The error preserves primary and
secondary cleanup/release failures through joined errors. In particular:

- Validation, stale conditions and cancellation observed before the decision
  interval are `NotCommitted`; cleanup failure can still require recovery.
- Once the decision can exist, failed publication, sync, close or settlement is
  `Unknown` with evidence retained. A namespace sync error never becomes success.
- A synchronized terminal receipt establishes `Committed`; subsequent cleanup or
  release errors still return an error with that committed outcome.
- Cancellation after the decision begins does not skip settlement or required
  synchronization. Recovery checks cancellation before changing state and then
  finishes its chosen safe sequence. Filesystem calls have no hard deadline.

`Recover(ctx)` is an explicit mutation entry point and does not bootstrap a
missing repository merely to check for recovery. A successful recovery with no
pending record reports `NotCommitted` for *no pending operation*; it is not a
receipt about an earlier call. Receipts are retired after cleanup. Lost responses
do not imply that a mutation failed, and there is no historical exactly-once API.

The guarantee is checked ordered file and namespace synchronization plus process-
interruption recovery on the tested native filesystem model. SIGKILL experiments
and successful fsync calls do not prove hardware power-loss ordering, drive-cache
flush behavior or every volume configuration. No synchronization failure is
silently ignored or downgraded to success. Stronger hardware guarantees,
arbitrary same-user exclusion, authenticated journals and historical epochs are
outside this delivery.

## Existing creation and passive commands

`Store.CreateContext` keeps canonical formatting and no-overwrite behavior, and
uses an outcome-bearing `profilerepo.OutcomeError` through its existing signature.
The existing builder exits with the actual error for committed, unknown or
recovery-required saves. It does not offer blind retry or label those saves as
cancelled. Ordinary pre-commit cancellation and ordinary success retain their
existing behavior.

Running the same `acs devin create-profile --name NAME` command interactively
reaches explicit Store recovery before the duplicate-name read, including when
a prior uncertain creation already published NAME. A valid name, live context
and required interactive streams are checked before this mutation-owned entry.
Recovery settles the earlier transaction first; an already-published Profile then
produces the existing duplicate-name error, without opening the builder or saving
again. Recovery failure is reported before duplicate detection. No unrelated
Profile must be created to reach recovery, and no new CLI command is needed.

`Store.Load`, repository Read, Profile list/show/validate and doctor do not invoke
recovery. Inspection and diagnostics retain their existing passive, non-snapshot
contracts and ignore non-`.json` transaction artifacts, including live or malformed
ones. Reads can observe the intermediate two-name rename state.

## Evidence and supported systems

The supported runtime remains macOS 26 arm64 and Intel. The current-head promoted
artifact workflow runs the full normal and race suites on both native architectures,
logs the actual filesystem's ASCII case-alias behavior and kernel ownership probe,
and retains installed-candidate, passive diagnostic, containment, Session and
credential-free authentication gates. Linux checks are development observations,
not native approval. The filesystem log describes only the CI volume actually
observed; it makes no claim about unrun volumes or hardware failure.

Repository regressions include exact future-codec bytes and empty documents,
stale independent writers, clone source freshness, exclusive destination races
from another process, inode interference despite equal bytes, stopped live owners,
process death and exec, raw-input bounds, malicious filesystem/journal entries,
restricted-identity permission denial, cancellation, partial writes, sync/close
failures and joined cleanup errors. Fresh helper processes SIGKILL at every traced
before/after mutation boundary and recover twice in new processes. Further matrices
interrupt recovery from commit, partial preparation and partially cleaned terminal
states, and exercise first-use directory creation rather than only existing roots.

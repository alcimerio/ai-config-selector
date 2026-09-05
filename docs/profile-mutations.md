# Edit, clone, rename and delete stored Profiles

These commands describe the development source on macOS 26, Apple Silicon and
Intel. They are not part of the published v0.4.0 binary. Build the current source
as described in the [README](../README.md).

```sh
acs profile edit backend-review
acs profile clone backend-review --name frontend-review
acs profile rename backend-review --name service-review
acs profile delete service-review
# Deliberate noninteractive deletion requires the exact matching name:
acs profile delete service-review --confirm service-review
```

Command words come first. After them, the single source `NAME` and separate-token
flags may appear in either order, for example `acs profile clone --name new old`.
Names use 1–64 ASCII letters, digits, dots, underscores or hyphens, starting with
a letter or digit. Clone/rename destinations must have a distinct name, including
case, and be absent. Unknown, duplicate, missing or attached flags (`--name=new`),
extra operands, `--`, `--yes`, force, overwrite and pass-through options are
rejected. Each command has contextual `--help`; help and malformed requests do
not inspect HOME, cwd, terminal capabilities, storage or runtime dependencies.

## Editing and selection repair

Edit opens the existing Profile Builder with the saved selections. Clone opens
the same builder under the new name with those selections initially preserved.
Both require usable interactive stdin and stdout, but do not require an installed
client, authentication, a Session, an active platform probe or a launch plan.

Open Skills with Enter. Use Up/Down to navigate, Space/Enter to toggle a row, `/`
to search, and Left/Esc to return. Esc inside search clears its filter first.
`R` refreshes sources while the Skills list has focus. A failed discovery offers
retry, back, or `E` to edit the saved selections even while discovery is unavailable.
Selections survive navigation, filtering, terminal resize, failed discovery and
refresh. A dirty draft requires confirmation before discard.

Rows are the union of saved selections and discovered choices, identified by
exact **source plus relative path**, not display name. A saved missing or
ambiguous identity remains visible and selected until you explicitly remove it.
Replacement means deselecting that identity and selecting the intended replacement;
an identically named Skill from another source never substitutes automatically.

Status distinguishes available, missing, ambiguous and unavailable/unchecked.
Missing roots/manifests can establish absence. A failed source read cannot do so;
it leaves that source unavailable/unchecked while readable sources still provide
replacement choices. These repair observations do not change the existing passive
inspection/validation or full launch discovery semantics. Source availability can
change later and is not a promise of launch readiness.

## Preview and commit

Choose Preview Edit or Preview Clone. Rename opens a compact old/new-name and
representation preview immediately. Scroll with Up/Down, PgUp/PgDn or End. Reach
the final preview page before confirming. A preview lists added, removed and
retained selections and shows the exact resulting canonical JSON. Retained
unresolved selections require a separate `A` warning acknowledgement before
Y/Enter can commit. Saving those structurally supported selections is allowed;
this does not install Skills or establish authentication/runtime readiness.

The preview explicitly discloses stored v1 → v2 conversion, including
`skillReferences` becoming `categories.skills` with category schema 1, missing
category defaults, selection sorting, field order, indentation and final newline.
It also discloses canonicalization of supported v2 representations. Even an
unchanged legacy selection requires this preview; there is no silent no-op
migration and no new persisted Profile schema. The commit closure owns exactly
the previewed bytes and captured expected revisions, rather than regenerating
bytes from later mutable editor state.

Supported-structure eligibility is checked against the bounded exact bytes read
with the revision, bound to the requested filename identity. Unknown fields,
future content, unsupported targets/categories/sources, duplicate keys, ambiguous
structure, unsafe references and filename/body identity mismatch refuse rewriting
without changing bytes, modes or the Profile tree. Permissive codec normalization
alone never authorizes editing, cloning or renaming.

## Conflicts and cancellation

Storage changes during an open editor cause a conditional commit conflict. The
newer stored data and current draft are preserved. There is no force retry. `L`
requests an explicit reload; `Y` then discards the preserved draft and reads a new
strict snapshot, while `N` keeps it. A fresh preview and confirmation are required
before another commit. Occupied clone/rename destinations, including malformed
entries and native filesystem aliases, are never overwritten. Other ordinary
save failures require a new preview before retrying.

Esc returns from a preview; Ctrl+C or Ctrl+D cancels before commit, with discard
confirmation when selections changed (exit 130). EOF, confirmation mismatch,
pre-commit cancellation and stale revisions never authorize deletion. Terminal
state is restored on completion, cancellation, signals and errors. If termination
arrives during an active save, ACS waits for the repository outcome rather than
assuming the operation failed. A committed transaction remains committed even if
a cancellation request or later cleanup error occurs.

## Deletion authority

Interactive deletion displays content status and requires typing the exact name,
then Enter. A mismatch clears the input and leaves the Profile untouched. Y/Enter
alone does not confirm deletion. Noninteractive use requires the exact matching
`--confirm NAME`; it still reads a bounded snapshot and deletes conditionally at
that revision.

A safely readable private regular document may be deleted even when corrupt or
unsupported; the preview prints a clear warning and never decodes/re-encodes its
bytes for deletion. Unsafe paths, nonregular entries, unexplained hard links and
other repository boundary violations are refused. Only the confirmed stored
Profile is in scope. Other Profiles, identities and active Session copies remain
untouched. There is no automatic undo.

## Uncertain outcomes and recovery

All mutations use the [revisioned repository](profile-repository-transactions.md).
Its Apply call owns recovery under the same stationary lock after confirmation;
preparation and cancellation do not create locks or journals. No second lock,
publication, journal or recovery engine is involved.

A committed-with-error result reports that the mutation committed and cleanup or
reporting failed, with a nonzero exit. An Unknown result says publication may
have occurred and prohibits blind retry. Recovery-required results retain that
status independently of commitment. These outcomes never become ordinary
cancellation, including when Ctrl+C was pressed or terminal execution ended.

Follow the command printed in the error, for example:

```sh
acs devin create-profile --name backend-review
```

This existing interactive creation entry point recovers before its duplicate
check. Cancel the builder if it opens, then use `acs profile list` and
`acs profile show NAME` to inspect the stored state before deciding what to do.
Recovery can finish the earlier operation; it is not rollback. Do not delete
transaction artifacts or bypass a live lock. The repository documentation explains
content revisions, concurrent-writer limits, two-name rename visibility and the
native filesystem durability model.

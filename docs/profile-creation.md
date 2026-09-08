# Declarative Profile creation

In development source beyond the published v0.4.0 release,
`acs profile create --file FILE [--dry-run]` validates or creates one
machine-local Profile from an explicit JSON file. The document supplies its
own name. Standard input and implicit file selection are not supported.

Only the currently supported version-3 representation is accepted. The exact
common `skills`, `workspace`, `paths`, `executables`, and `environment`
capabilities and supported version-1 `devin` and `codex` overlays may be
present. Environment source names and secret references are validated as
logical local bindings; provider values are never read by creation or dry-run.
Future envelope versions, legacy v1/v2
documents, duplicate keys, unknown fields or common capabilities, unsupported
or unknown overlays, invalid references and any representation that cannot be
preserved losslessly are rejected. Existing legacy read, edit and migration
behavior is unchanged.

The input must be a regular file no larger than 1 MiB. ACS opens it
nonblocking, validates the opened descriptor and reads that descriptor once;
FIFOs, devices and directories are rejected without waiting for content.
Symlinks to regular files are deliberately supported. Replacing the source
pathname after it is opened does not change the captured candidate. ACS never
changes the input bytes or mode.

Missing Skill material and absent named Codex authentication are not structural
errors. Exact valid Skill source and relative-path identities and the opaque
`authRef` are preserved without discovery, display-name rebinding or repair.
Creation does not require a TTY, target executable, provider access, native
sandbox probe, Session or process.

## Preview and publication

`--dry-run` prints the deterministic canonical JSON that would be published,
including normalized field ordering, indentation, final newline and supported
defaults. It also states which availability and runtime properties remain
unchecked. Dry-run passively checks that the destination is absent but creates
no Profile directory, lock, journal, Session, credential or other durable file.

Without `--dry-run`, the valid invocation is explicit authorization to publish;
there is no terminal confirmation. ACS recovers the repository through its
existing transaction lock and calls the same conditional, no-overwrite Profile
Store creation transaction used by the interactive Profile Builder. It does
not reread the source after validation. An occupied destination, concurrent
winner, cancellation before publication or invalid input does not replace or
modify a stored Profile.

If ACS reports that publication committed and only output reporting failed, the
Profile exists and repository recovery is not required; inspect it before doing
anything else. A committed outcome with cleanup failure does require recovery.
If ACS reports an unknown outcome, publication may have occurred and recovery
is also required. For recovery-required outcomes, do not blindly retry or
delete transaction artifacts; follow the printed recovery command, cancel the
Builder if it opens, and inspect the stored name with `acs profile list` and
`acs profile show NAME` before deciding what to do.

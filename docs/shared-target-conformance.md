# Shared Devin and Codex behavior and evidence

ACS supports one common Profile contract across its maintained Devin and Codex
adapters. A version-3 Profile selects global Skills by exact `source` plus
`relativePath` identity and declares either read-only or explicit read-write
workspace intent. Both targets consume the same resolved common copy under
`.acs/common/v1/skills`; unselected global bundles are excluded. The private
writable Session, containment policy and process lifecycle remain owned by ACS.

The target projections are intentionally different. Devin receives selected
bundles in its `.config/devin/skills` and `.agents/skills` roots and its plan
reports repository-local `.devin/skills` and `.agents/skills` inheritance.
Codex receives selected bundles under
`.codex/skills/<source>/<relativePath>`. Codex can discover permitted
repository-local `.agents/skills` through the workspace, but ACS does not
materialize or describe those files as selected global material. A read-only
grant still permits workspace reads; it is not a promise to hide project files.

Authentication is not common Profile data. A Codex overlay contains only an
opaque named reference, and `--auth` changes the effective reference for one
run without rewriting the stored reference. ACS never falls back to global
Codex authentication. Codex dry-run checks stored structure and reference
syntax without source discovery, credential access, target execution or
Session creation. Devin retains its separate allowlisted
`.local/share/devin/credentials.toml` contract and contained `auth status`
preflight. Automated tests use credential-free fixtures; authenticated tests
require separate explicit local authorization and must not run in CI.

Legacy version-1 and version-2 Profiles remain Devin-bound, retain their
writable workspace grant and use their established target paths. Inspection or
launch never silently reinterprets them as Codex. `acs profile migrate NAME` is
the explicit boundary that creates a version-3 common Profile; adding and using
a Codex overlay remains a separate deliberate choice. Unsupported selected
overlays and cross-target combinations fail before source discovery, target
execution or Session creation. Unknown inactive overlays remain inert, and
rewrite commands refuse them when lossless preservation cannot be proved.

## Automated evidence boundary

`TestMaintainedTargetsShareCommonSkillsAndWorkspaceContract` in
`internal/adapter/conformance_test.go` is the shared credential-free behavioral
suite. It drives both adapters through their category resolution and planning
boundaries, checks common identities and workspace intent, verifies selected
and unselected material, checks per-target projections and project-local
inheritance, and proves the legacy and unsupported-overlay boundaries. It does
not claim installed-target discovery or actual daily use.

The executor suites retain stronger production-composition proofs instead of
being replaced by a table of test names:

- `TestRunEntrypointsEarlyPhaseMatrix` proves containment checks precede
  Sessions and process preparation for the credential-free shell and Devin.
- `TestRunShellFailedStartDoesNotWaitRetainsThenRemovesSession`,
  `TestRunShellFailedWaitRetainsThenRemovesSession`,
  `TestRunShellCleanupUncertaintyOutranksOrdinaryExitAndRetainsSession` and
  `TestRunDevinAttachedWaitsOnceAfterReplayFailure` cover Start/Wait counts,
  cleanup uncertainty and cleanup-over-outcome precedence.
- `TestRunAttachedForwardsSignalReceivedDuringStartupAndWaits`,
  `TestInteractiveReservationPreservesTerminationAgainstResize` and the Codex
  execution signal tests cover cancellation, terminal signals and settlement.
- Codex binding and recovery tests preserve projected authentication and
  quarantined Sessions until cleanup is confirmed.

On macOS 26 Apple Silicon, `TestPromotedArtifactSharedTargetConformance` runs
both public dry-run paths against the supplied ACS candidate without rebuilding
it. The same native job preserves the real Seatbelt, PTY, race, Keychain,
recovery, zombie/descendant and checksum-locked `codex-cli 0.149.1` gates.
Behavioral target fixtures prove ACS orchestration and placement only. They do
not prove actual installed Devin discovery, a real account, target-origin
refresh or week-long work. Linux and Intel are not native support evidence.

## Ten-minute quickstart target

The following is a practical target, not a measured claim. On a supported Mac
with a source-built candidate, one existing Skill and the required target
already installed, aim to reach a useful Profile within ten minutes:

```sh
acs doctor
acs doctor --target devin
acs devin create-profile --name backend-review
acs profile validate backend-review
acs profile show backend-review
acs sandbox --profile backend-review --dry-run
acs devin --profile backend-review --dry-run
acs codex --profile backend-review --auth work --dry-run
```

Use the builder to select the same common Skills and choose read-only or the
explicit `Read and write (coding work)` grant. Create the named Codex identity
separately with `acs codex auth login --name work`; never record its credential
or account output. A Profile needs a supported Codex overlay before the Codex
commands above are valid.

## Daily-use checklist

The full milestone is pending until a person completes these observations with
authorized accounts. For two real projects, use both Devin and Codex for one
week and record the exact ACS artifact SHA-256/version and exact target versions.
For each project and target:

- inspect with `profile show` and `profile validate`; safely exercise clone,
  edit, rename and delete on disposable Profile names, including cancellation;
- confirm the same selected common Skills appear with the documented target
  projections, while unselected global Skills do not;
- exercise read-only review and explicit coding-write work, checking the
  workspace result and that unrelated paths remain unavailable;
- for Codex, select the intended named identity, perform real work, close the
  terminal normally, interrupt once, and follow `auth status`/`auth recover`
  guidance if ACS reports uncertain cleanup;
- for Devin, confirm its normal credential preflight without copying or
  displaying credential contents;
- exercise terminal input/output, resize, cancellation and a descendant task;
  after each run confirm no active Session remains unless ACS explicitly
  quarantined it for recovery;
- run actionable diagnostics before and after the observation and record only
  stable public categories, never private target output.

No real-use observation has been supplied for this change, so elapsed days,
accounts, projects, target refresh and actual daily-use success are
**unperformed/pending**.

## Sanitized observation template

```text
Date (timezone):
Project alias (not a private path):
Target: Devin | Codex
ACS artifact version and SHA-256:
Target version:
Profile envelope version:
Selected Skill identities (source:relativePath only):
Workspace intent: read-only | read-write
Operation: inspect | clone | edit | rename | delete | launch | recover
Public result category and exit code:
Workspace write observed: allowed | denied | not attempted
Terminal/signal/descendant cleanup observed:
Session state after return: absent | quarantined for recovery
Diagnostics result (public categories only):
Actual-use status: performed | pending
Notes (no credentials, account data, target output, paths or Session contents):
```

# ACS open-source readiness review

[Documentation index](../README.md)

Review date: 2026-09-30. Source baseline: `6d7e3d0e2705e169395b655dbffdf435435fdb54`.
This report prioritizes concrete follow-up work and records the documentation
review. It is not a complete security audit or new native-runtime certification.

## Summary

ACS has substantial implementation and evidence documentation, but the entry
point had become a feature ledger: installation appeared after several long
reference sections, current and historical behavior overlapped, and some examples
no longer matched the implementation. The highest-leverage change is a clear
learning path with precise links to the existing detailed contracts.

This change reviews all **50 pre-existing Markdown files**, adds six documents
(including this report), and adds offline navigation regression tests. It changes
no production Go code, workflows, release bytes/tags, license, or security settings.
No existing issues are closed and no speculative issue batch is created.

## Documentation work completed

- Replaced the long README with purpose, supported platform, preserved
  checksum-verified install examples, first sandbox workflow, limitations, and navigation
- Added a documentation index/glossary, step-by-step onboarding, CLI guide,
  security-model summary, and symptom-oriented troubleshooting
- Corrected v3 read-only defaults, common capabilities/overlays, additional
  filesystem grants, selected-secret scope, Codex-specific authentication and
  dry-run boundaries, and the lack of per-tool approval prompts
- Repaired a dual-target quickstart that launched Codex with a Devin-only Profile
- Corrected inspection JSON fields/omissions and diagnostics' ten-check contract
- Fixed a portable exchange example whose unused binding made validation fail
- Replaced foreign-binary-executing cross-compilation commands with compile-only
  commands, and corrected native-gate recovery-trap/release preparation instructions
- Marked historical notes, unpublished candidates, research, and fixtures clearly;
  preserved recorded results, unknowns, incomplete checklists and target-facing fixture bytes
- Preserved the v0.5.0 release notes byte-for-byte; fresh GitHub metadata matched
  the publication record, installer digest, and historical asset tables checked

## Prioritized follow-up backlog

### P2: Human inspection reports zero selected non-Skill capabilities

**Evidence:** [`internal/cli/inspection.go`, lines 76–85](../../internal/cli/inspection.go)
uses `len(category.Selection)` for every category. That field contains only Skill
references. Instruction references are in `Category.Instructions`; path,
executable, environment and MCP details are intentionally omitted by the public
inspection structure in [`internal/profileinspect/inspection.go`](../../internal/profileinspect/inspection.go).

**Reproduced:** with a disposable home and a benign v3 Profile selecting one
readable `acs-instructions:guide.md`, `profile show` prints
`instructions: 0 selected; stored category version: 1`, while JSON includes the
instruction reference and `explain sandbox` succeeds. The exact
[MCP Profile example](../mcp-profiles.md) has one path, one executable, three
environment entries and one server, but human inspection prints zero for each.

**Impact:** a person reviewing access can incorrectly conclude a selected capability
is absent. This is a presentation defect, not evidence that launch drops the grants.

**Next change / acceptance:** render sanitized capability-specific counts, or label
redacted categories as structurally present rather than zero. Render instruction
references separately. Add paired human/JSON regressions for nonempty instructions,
paths, executables, environment and MCP. The [inspection guide](../profile-inspection.md)
now states the current limitation; fixing it belongs in a focused product PR.

### P3: Shell release-version parsers admit a trailing dot

**Evidence:** [`scripts/release-tag-identity.sh`, lines 23–39](../../scripts/release-tag-identity.sh)
splits components with `IFS=.`; shell splitting drops a trailing empty component.
The same pattern occurs in `release-candidate.sh` and `prepare-release-tag.sh`.

**Reproduced:** the actual identity script returned success for `v1.2.3.` in a
disposable fake-git fixture that supplied matching clean tag/HEAD and notes.
No real tag, release, or remote state was created.

**Impact and limit:** early canonical-version validation is inconsistent. This is
not a demonstrated malformed-release publication path: downstream
[`tools/releaseverify`](../../tools/releaseverify/main.go) and
[`publish-release.sh`](../../scripts/publish-release.sh) use stricter anchored
validation and reject the malformed version.

**Next change / acceptance:** reject leading/trailing/consecutive dots in all
shell entry points, use one consistent canonical-version rule, and add trailing-dot
regressions alongside valid, leading-zero, prerelease and malformed cases.

### Maintainer decision: establish private vulnerability reporting

No `SECURITY.md` or private disclosure contact/process was present in the reviewed
checkout. Public issue templates alone would be unsuitable for credentials or
sensitive reproductions.

**Next change / acceptance:** choose a maintained private reporting route, document
its actual availability and supported-version scope, and state a response policy
only if the maintainer can honor it. Enabling GitHub security features or publishing
contact details is a separate maintainer decision; this PR makes no such change.
The [security guide](../security-model.md) currently avoids inventing an address or SLA.

### Existing release/evaluation work: reconcile rather than duplicate

The open issues at review time were
[#102 (release cut)](https://github.com/alcimerio/ai-config-selector/issues/102),
[#103 (exact native artifact)](https://github.com/alcimerio/ai-config-selector/issues/103),
[#104 (migration/rollback)](https://github.com/alcimerio/ai-config-selector/issues/104),
and [#105 (daily-use evaluation)](https://github.com/alcimerio/ai-config-selector/issues/105).
There were no open PRs when this review began.

v0.5.0 is already published; #102–104 should be reconciled against their exact
acceptance evidence, not copied into new issues or automatically closed by a docs
review. #105 still requires actual one-week observations with both targets in two
real projects. CI, publication and this review cannot supply elapsed daily use.

**Next change / acceptance:** update the existing issue checklists with verified
source/artifact/native evidence and record any unmet items separately. Complete
#105 only from the requested real-use observation.

## Verification and limits

Review environment: Linux amd64, official checksum-verified Go 1.27.1. The supported
production platform is macOS 26 Apple Silicon; these Linux checks are development
observations, not native containment or release-certification evidence.

Passed locally:

- `go test ./scripts` including documented installer, upgrade and migration examples
- Offline relative-document link and index-coverage tests added in
  [`scripts/documentation_links_test.go`](../../scripts/documentation_links_test.go)
- `go test -run '^$' ./...` (build plus package initialization; no selected test bodies)
- `go vet ./...` and CLI build
- Exact new CONTRIBUTING `go test -c` snippet for Linux amd64 and arm64
- Focused CLI, Profile, common capability, inspection, exchange, diagnostics,
  repository, history, instruction, MCP, Session, adapter, generic-command,
  authentication and selected executor tests
- Thirteen isolated CLI/example smoke checks, including strict Profile JSON
  admission, exact inspection JSON, ten diagnostic IDs, instruction availability
  boundaries, and original-failing/corrected-passing exchange bindings
- Local Markdown heading-fragment checks and `git diff --check`

A full `go test ./...` was also attempted and **did not pass** in this restricted
Linux environment. The same failing test names reproduced on the untouched
baseline commit. The executor tests require a writable real home; launch tests
encountered unsupported native Bubblewrap, denied Unix sockets, restricted host
paths/environment and process-monitor limitations. Those failures are not labeled
as passing or silently excluded from the aggregate result. Native CI is required
before a merge-ready claim.

Not re-executed locally: macOS Seatbelt/Keychain, native installed-artifact gates,
interactive target logins, authenticated provider behavior, Apple distribution
checks, hardware durability, or real daily-use observations. Existing historical
native results remain attributed to their recorded commits/runs. External links
were not exhaustively re-fetched; local paths/index coverage were checked, and
release metadata/source references were sampled or cross-checked as described above.

## Complete original-document inventory

Every original Markdown file below was read. “Retained” is an explicit decision,
not an omission. Detailed normative documents were corrected selectively rather
than rewritten for cosmetic consistency. New guides are listed separately after
the inventory.

| Original document | Disposition and reason |
| --- | --- |
| [CONTRIBUTING.md](../../CONTRIBUTING.md) | Corrected compile-only checks, recovery traps, release preparation and current evidence navigation |
| [README.md](../../README.md) | Reworked as the newcomer entry point; preserved verified installation examples and safety limits |
| [acceptance/testdata/devin-synthetic-credentials.provenance.md](../../acceptance/testdata/devin-synthetic-credentials.provenance.md) | Labeled fixture-only provenance; preserved original evidence/digest |
| [docs/architecture.md](../../docs/architecture.md) | Corrected v3 common/overlay model, default authority, module ownership and cleanup flow |
| [docs/authenticated-codex-auth-smoke.md](../../docs/authenticated-codex-auth-smoke.md) | Clarified supported architecture and owner-compatible recovery |
| [docs/authenticated-release-smoke.md](../../docs/authenticated-release-smoke.md) | Removed obsolete fixed v0.4.0 candidate; clarified identity and failure recovery |
| [docs/codex-auth.md](../../docs/codex-auth.md) | Corrected snapshot order, companion/provenance, quarantine and shared-Session authority |
| [docs/common-profile-format.md](../../docs/common-profile-format.md) | Retained accurate schema/authority contract; added index navigation |
| [docs/contained-process-executor.md](../../docs/contained-process-executor.md) | Updated entrypoints, grants, Devin rules probes and readiness/cleanup distinctions |
| [docs/current-candidate-handoff.md](../../docs/current-candidate-handoff.md) | Marked expired candidate history without changing pinned identity/evidence |
| [docs/effective-capability-explanation.md](../../docs/effective-capability-explanation.md) | Added selected instruction capture/semantic facts and navigation |
| [docs/extension-assessment.md](../../docs/extension-assessment.md) | Labeled research/test audience and latest-recorded scope; preserved frozen observations |
| [docs/generic-run.md](../../docs/generic-run.md) | Corrected grants, selected secrets, MCP non-activation, dry-run and network limits |
| [docs/instruction-bundles.md](../../docs/instruction-bundles.md) | Clarified Codex common-material/no-native-projection boundary and structure |
| [docs/interactive-codex.md](../../docs/interactive-codex.md) | Clarified overlay/auth requirements, no-prompt mode and shared credential authority |
| [docs/manual-upgrade-recovery.md](../../docs/manual-upgrade-recovery.md) | Retained verified published/candidate recovery and backup limitations unchanged |
| [docs/mcp-profiles.md](../../docs/mcp-profiles.md) | Retained strict schema and shared-authority limits; added navigation |
| [docs/native-transport-research.md](../../docs/native-transport-research.md) | Matched workflow test filter and actual evidence-retention window |
| [docs/outbound-network-enforcement.md](../../docs/outbound-network-enforcement.md) | Retained research decision and proof limits; added audience/navigation |
| [docs/passive-diagnostics.md](../../docs/passive-diagnostics.md) | Corrected ten-check order, codes and source-resolution boundaries |
| [docs/portable-profile-exchange.md](../../docs/portable-profile-exchange.md) | Repaired mismatched binding example and documented instruction/overlay behavior |
| [docs/profile-creation.md](../../docs/profile-creation.md) | Corrected current scope, reference-only validation and concurrent-write/cancellation limits |
| [docs/profile-history.md](../../docs/profile-history.md) | Retained normative contract; clarified placeholder IDs and navigation |
| [docs/profile-inspection.md](../../docs/profile-inspection.md) | Corrected exact JSON contract; added known human-count limitation and navigation |
| [docs/profile-mutations.md](../../docs/profile-mutations.md) | Clarified current scope, onboarding and case-only name restrictions |
| [docs/profile-repository-transactions.md](../../docs/profile-repository-transactions.md) | Retained normative protocol/evidence limits; added navigation |
| [docs/release-migration-guide.md](../../docs/release-migration-guide.md) | Clarified private export directory and resuming after fail-fast shell exit |
| [docs/release-readiness.md](../../docs/release-readiness.md) | Removed stale pending-documentation wording; retained publication/daily-use separation |
| [docs/releases/v0.2.0-checklist.md](../../docs/releases/v0.2.0-checklist.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.2.0.md](../../docs/releases/v0.2.0.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.3.0-checklist.md](../../docs/releases/v0.3.0-checklist.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.0.md](../../docs/releases/v0.3.0.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.1-checklist.md](../../docs/releases/v0.3.1-checklist.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.1.md](../../docs/releases/v0.3.1.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.2-checklist.md](../../docs/releases/v0.3.2-checklist.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.2.md](../../docs/releases/v0.3.2.md) | Labeled unpublished historical candidate; pinned evidence links and preserved incomplete records |
| [docs/releases/v0.3.3-checklist.md](../../docs/releases/v0.3.3-checklist.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.3.3.md](../../docs/releases/v0.3.3.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.4.0-checklist.md](../../docs/releases/v0.4.0-checklist.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.4.0.md](../../docs/releases/v0.4.0.md) | Labeled historical release; preserved version-specific capabilities and recorded evidence |
| [docs/releases/v0.5.0-checklist.md](../../docs/releases/v0.5.0-checklist.md) | Retained byte-for-byte; verified current published notes/asset metadata and remaining evidence limits |
| [docs/releases/v0.5.0.md](../../docs/releases/v0.5.0.md) | Retained byte-for-byte; verified current published notes/asset metadata and remaining evidence limits |
| [docs/session-operations.md](../../docs/session-operations.md) | Retained proof-gated contract; clarified real Session IDs and navigation |
| [docs/shared-target-conformance.md](../../docs/shared-target-conformance.md) | Fixed invalid dual-target quickstart; preserved evidence/daily-use boundaries |
| [internal/adapter/devin/testdata/selected-skill/SKILL.md](../../internal/adapter/devin/testdata/selected-skill/SKILL.md) | Retained byte-for-byte as deterministic target-facing Skill/agent fixture; owning README explains purpose |
| [internal/executor/testdata/devin-rules-renderer/README.md](../../internal/executor/testdata/devin-rules-renderer/README.md) | Corrected separator description and fixture/native evidence distinction |
| [internal/extensionassessment/testdata/README.md](../../internal/extensionassessment/testdata/README.md) | Clarified fixture-only purpose and target-input Markdown semantics |
| [internal/extensionassessment/testdata/codex/plugin/skills/reviewer/SKILL.md](../../internal/extensionassessment/testdata/codex/plugin/skills/reviewer/SKILL.md) | Retained byte-for-byte as deterministic target-facing Skill/agent fixture; owning README explains purpose |
| [internal/extensionassessment/testdata/devin/agents/reviewer.md](../../internal/extensionassessment/testdata/devin/agents/reviewer.md) | Retained byte-for-byte as deterministic target-facing Skill/agent fixture; owning README explains purpose |
| [internal/extensionassessment/testdata/devin/plugin/skills/reviewer/SKILL.md](../../internal/extensionassessment/testdata/devin/plugin/skills/reviewer/SKILL.md) | Retained byte-for-byte as deterministic target-facing Skill/agent fixture; owning README explains purpose |

New documentation: [index/glossary](../README.md), [getting started](../getting-started.md),
[CLI guide](../cli.md), [security model](../security-model.md),
[troubleshooting](../troubleshooting.md), and this review report.

## Suggested order after this PR

1. Land the documentation only after the exact draft-PR native checks are reviewed
2. Fix the misleading inspection counts in a small tested product PR
3. Resolve the private-reporting decision and reconcile #102–104 with existing evidence
4. Fix shell version validation in a separate tooling PR
5. Finish #105 from actual daily-use observations, without upgrading CI into a real-use claim

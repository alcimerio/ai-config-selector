# Next release preparation

This is the source-level handoff for a future stable ACS release. It does not
assign a version, designate an artifact, report completed daily use, or announce
a release. The proposed cut remains unpublished until the exact package has
completed the remaining checks below and the authorized maintainer has approved
publication.

## Comparison boundary

The prepared source boundary is commit
`be3015f603ab2ba3391818a357847b0db9b22388`, tree
`f0980625c424f8f9369fc86b6123564fd51bd6c5`. Compare it with the immutable
published v0.4.0 annotated tag object
`847e9ef3ae32e8a306213295ff14ad297bbaa5d2`, which resolves to commit
`d5f333c0cf4e32334a92c5fca77a8af0bcb4cd64` and tree
`3b7bda60823fc4b7c32c1d15b5870e67bb1630a1`.

That comparison describes current source, not v0.4.0 artifacts. Published
v0.4.0 remains immutable and includes historical `darwin/arm64` and
`darwin/amd64` artifacts. Current source and a future release support only macOS
26 on Apple Silicon (`darwin/arm64`); the old Intel artifact is recovery evidence
for v0.4.0, not a current support promise.

The future release uses the existing stable numeric `vMAJOR.MINOR.PATCH`
channel. Current preparation, tag, candidate, and publication interfaces reject
prerelease versions, and publication sets `prerelease=false`. This review does
not introduce another channel.

## User-visible source scope

In addition to the v0.4.0 Devin Profile creation and launch, sandbox shell,
dry-run, and version interfaces, the prepared source includes:

- contextual help, passive host diagnostics, and passive Profile list, show,
  and validation;
- revision-bound Profile create, edit, clone, rename, and delete operations,
  explicit transaction recovery, and bounded local history for adopted
  Profiles;
- Profile v3 common Skills and workspace authority shared by Devin and Codex,
  explicit legacy migration, declarative JSON creation, and sanitized portable
  export/import with explicit local bindings;
- one shared contained-process lifecycle, literal argv-only generic command
  execution, and sanitized effective-authority explanation;
- interactive, checksum-locked `codex-cli 0.149.1` with isolated named ChatGPT
  authentication, rather than ambient Codex credentials (the current
  `darwin/arm64` archive lock is SHA-256
  `ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405`); and
- durable Session list, inspect, and conservative recovery operations.

The detailed operating contract stays in the focused guides linked from the
[README](../README.md). The [candidate migration and rollback
guide](release-migration-guide.md) is the operator procedure for staging the
eventual exact artifact without treating binary selection as data migration.

## Compatibility and limitations

- Profile envelopes v1 and v2 remain readable. Ordinary inspection is passive;
  only `acs profile migrate NAME` deliberately adopts v3. A successful current
  source mutation may canonicalize a legacy Profile as v2. Migration retains
  legacy workspace write authority, and changing that authority is a separate
  decision.
- Profile schema, transaction, history, Session, authentication, and portable
  exchange formats have separate ownership and recovery rules. Binary rollback
  does not downgrade data. Keep a compatible owning binary until pending work is
  settled or recovered.
- Portable exchange transfers sanitized logical intent, not Skill contents,
  local paths, history, Sessions, authentication, or readiness proof. Local
  history is bounded rollback assistance, not a backup.
- Interactive Codex is limited to the locked version, named ChatGPT identities,
  common Skills, and declared workspace access. ACS does not expose arbitrary
  target arguments, MCP configuration, plugins, API-key import, backend choice,
  or generic Codex configuration passthrough.
- The supported native boundary is the system Seatbelt backend on macOS 26
  Apple Silicon. Linux compilation is a non-blocking portability observation,
  not release evidence. Intel is not a current source or future release target.
- ACS has no automatic updater, package-manager distribution, uninstaller, or
  network destination filter. It does not make target output or third-party
  service behavior trustworthy.
- Release archives are presently unsigned and unnotarized. SHA-256 proves byte
  identity against a trusted digest, while GitHub attestation supplies separate
  origin evidence; neither supplies Apple Developer ID signing, notarization,
  malware review, or Gatekeeper approval. No unsigned Gatekeeper distribution
  has been validated by this preparation.

## Publication controls inspected

The following public repository and workflow metadata was inspected read-only on
2026-09-07. No credential value or private account content was read.

- Protected `main` is implemented by an active repository ruleset. It requires
  pull requests, linear history, resolved review threads, and the `Verify
  (macOS)` and `Native darwin/arm64` status checks. The ruleset exposes an
  administrator bypass; the release decision must not rely on using it.
- Active tag rulesets restrict creation of `refs/tags/v*` to the configured
  maintainer bypass identity and prohibit tag update or deletion without a
  bypass. `scripts/publish-release.sh` independently re-reads the exact ruleset
  structure and verifies that the event actor matches the configured creator.
- The `release` environment accepts only its custom `v*` tag policy. Its public
  metadata shows no required reviewer or wait timer and permits administrator
  bypass, so the required final human publication approval remains an explicit
  custody step rather than evidence supplied by the environment configuration.
- Immutable GitHub Releases are enabled. The repository does not globally
  require action SHA pinning, but every action used by the release workflow is
  pinned to a full commit in the inspected source.
- The tag workflow accepts an annotated stable tag, validates its tag object,
  source commit, release notes, and protected-main ancestry, then builds one
  candidate. The same candidate bytes are installed and exercised on native
  macOS 26 Apple Silicon before the archive and checksum manifest are attested.
  Publication downloads that artifact without rebuilding it, revalidates its
  exact contents, stages an exact draft asset set, and publishes it once through
  the `release` environment.
- `scripts/prepare-release-tag.sh` requires a clean, current `main` matching the
  fetched `origin/main`, a new canonical numeric tag, and version-specific
  release notes. It creates an annotated local-only tag and prints the one exact
  ref that may be pushed after approval.

The configured actor and ruleset identifiers can be checked as non-secret
metadata. Whether the environment variables still name those exact identifiers,
whether its GitHub App private key and tokens are usable, and who currently has
custody of the authorized accounts cannot be established without using protected
configuration or credentials. Those checks belong to the final controlled cut;
their values must not be copied into logs or release documents.

## Readiness assessment

| Area | Status at this source boundary | Evidence and remaining action |
| --- | --- | --- |
| Source scope | **Complete for review** | The exact source commit/tree and immutable v0.4.0 comparison are recorded above. Freeze the final cut at a reviewed commit descended from this boundary and record any intervening changes. |
| Candidate and target identity | **Needs final substitution** | Choose the final stable version, add `docs/releases/vMAJOR.MINOR.PATCH.md`, and run the clean-main tag preparation interface. Record the annotated tag object, source commit/tree, locked Codex archive and executable digests, candidate archive digest, and installed ACS binary digest. A development candidate labelled v0.4.0 is not the published v0.4.0 artifact. |
| Native installed-artifact checks | **Needs final artifact execution** | The release workflow contains macOS 26 Apple Silicon normal, race, installed-artifact, containment, terminal, denial, lifecycle, Session recovery, and shared Devin/Codex gates. Run them from the final tag against the candidate built in that run and retain job URLs and sanitized operation witnesses. PR candidate artifacts and source tests do not substitute for final-tag bytes. |
| Codex authentication evidence | **Needs final artifact execution and optional operator observation** | Automation uses the official checksum-locked CLI, a loopback simulated API, synthetic authentication, and a disposable Keychain. It proves the tested isolated composition, not a maintainer account, hosted inference, quota, or refresh. Any real-account smoke is separately authorized, credential-safe supplemental evidence. |
| Documentation, migration, and rollback | **Complete for an unnumbered candidate; needs final substitution** | The candidate guide covers compatibility, exact-byte installation, explicit migration, nonzero recovery, binary rollback, and the two-project observation template. Re-run its tested shell examples and replace placeholders only after the final version and artifacts exist; preserve every historical release document. |
| Artifact trust | **Controls prepared; needs final evidence** | Retain the final build-once artifact name, checksums, native job, attestation verification, draft asset comparison, publication job, and immutable Release result. Do not infer final evidence from a PR artifact or from synthetic authentication. |
| Apple signing and notarization | **Custody decision required** | Decide before publication whether the cut remains explicitly unsigned/unnotarized or is blocked for a separately reviewed signing flow. There is no signing/notarization machinery in this source, and checksums or attestations cannot fill that gap. Do not weaken Gatekeeper or claim unsigned distribution was validated. |
| Two-project daily use | **Operator observation required** | Use the exact selected candidate with both Devin and Codex in two real projects for one full week on macOS 26 Apple Silicon. Complete the sanitized template in the migration guide, including quickstart usefulness, Skills/workspace behavior, named-auth isolation, terminal behavior, cleanup/recovery, elapsed dates, and blockers. CI and synthetic authentication cannot complete this item. |
| Final version and publication | **Approval required** | Review the completed exact-head package and evidence, choose the stable version, confirm release identity/configuration custody, and obtain explicit approval before pushing the annotated tag. Keep the Release unpublished if any required evidence or approval is absent. |

Issues [#102](https://github.com/alcimerio/ai-config-selector/issues/102),
[#103](https://github.com/alcimerio/ai-config-selector/issues/103),
[#104](https://github.com/alcimerio/ai-config-selector/issues/104), and
[#105](https://github.com/alcimerio/ai-config-selector/issues/105) remain open.
This preparation completes none of their final-artifact, custody, or elapsed-use
requirements by itself.

## Final operator handoff

1. Land and independently review all intended source changes, then freeze the
   exact protected-main commit and tree. Confirm issue scope and decide the
   numeric stable version; do not reuse an existing tag.
2. Create the matching version-specific release notes and checklist without
   modifying historical release documents. Record the signing/notarization
   decision and the source boundary.
3. From a clean, up-to-date `main`, run `scripts/release-candidate.sh
   vMAJOR.MINOR.PATCH` for a local review, then `scripts/prepare-release-tag.sh
   vMAJOR.MINOR.PATCH`. Review the emitted source and annotated-tag identities.
4. After explicit approval for that exact local tag, push only
   `refs/tags/vMAJOR.MINOR.PATCH`. Monitor the tag workflow through candidate,
   native validation, attestation, and protected publication. Never move or
   delete the tag; fix a failed cut in source and choose a new version.
5. Retain the exact public and private evidence named in the table. Verify the
   published asset set and attestation only if the workflow was authorized to
   publish. Keep all issues open until their own acceptance evidence is present.

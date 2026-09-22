# v0.5.0 release evidence and remaining observation

The [ACS v0.5.0 Release](https://github.com/alcimerio/ai-config-selector/releases/tag/v0.5.0) is published as a stable, latest, immutable GitHub Release for macOS 26 on Apple Silicon (`darwin/arm64`). The version-controlled [release notes](releases/v0.5.0.md) match its public body. The [publication record](releases/v0.5.0-checklist.md) gives the exact asset URLs, sizes, digests, workflow links, and trust limits. The one-week, two-project Devin/Codex observation remains **UNPERFORMED / PENDING** in [issue #105](https://github.com/alcimerio/ai-config-selector/issues/105).

The immutable Release body links to documentation at the v0.5.0 tag, where the
manual recovery and candidate guides retain pre-publication wording. Use the
current [main-branch manual recovery guide](https://github.com/alcimerio/ai-config-selector/blob/main/docs/manual-upgrade-recovery.md)
and [candidate guide](https://github.com/alcimerio/ai-config-selector/blob/main/docs/release-migration-guide.md)
for corrected procedures after this documentation update lands.

## Source and release identity

The final annotated tag object is `530f7349b63605cd953629ba5ff860d6c3f41c81`; it peels to protected-main commit `715d2a0d6e288ebf764255b0616297741cb04946` and tree `487c42b668476de22110dffc530529f7bf623959`. The [release workflow run 35796440099](https://github.com/alcimerio/ai-config-selector/actions/runs/35796440099), attempt 1, passed candidate, native macOS validation, attestation, and publication. The parallel [macOS validation run 35796440184](https://github.com/alcimerio/ai-config-selector/actions/runs/35796440184) passed. The public Release API reports `draft=false`, `prerelease=false`, `immutable=true`, and latest `v0.5.0`.

The historical preparation comparison on 2026-09-07 used source commit `be3015f603ab2ba3391818a357847b0db9b22388`, tree `f0980625c424f8f9369fc86b6123564fd51bd6c5`, against immutable v0.4.0 annotated tag `847e9ef3ae32e8a306213295ff14ad297bbaa5d2`, commit `d5f333c0cf4e32334a92c5fca77a8af0bcb4cd64`, and tree `3b7bda60823fc4b7c32c1d15b5870e67bb1630a1`. That earlier source boundary is distinct from the final v0.5.0 tag. Published v0.4.0 retains historical `darwin/arm64` and `darwin/amd64` assets; the Intel asset is not a v0.5.0 support promise.

## Published capability and compatibility

Compared with v0.4.0, v0.5.0 adds passive Profile inspection and diagnostics; confirmed Profile mutations, declarative creation, portable exchange, explicit migration, and bounded history; shared v3 Skills and workspace authority; selected instruction references, filesystem and executable grants, scoped environment references, and reference-only local STDIO MCP servers; literal contained command execution; effective-authority explanation; interactive Codex with isolated named ChatGPT authentication; durable Session operations; and explicit stable-release update checks and executable replacement. The [README](../README.md) and [release notes](releases/v0.5.0.md) link to the focused operating contracts.

Profile v1/v2 remains readable, while `acs profile migrate NAME` deliberately adopts v3. A binary rollback does not downgrade Profiles, history, Sessions, named authentication, or transaction evidence. Keep a compatible owning v0.5.0 binary to inspect or recover newer state. Portable exchange moves sanitized logical intent, not local files, credentials, history, Sessions, or readiness proof. The v0.4.0 binary has no `acs update`, so its users must bootstrap the [published v0.5.0 installer](https://github.com/alcimerio/ai-config-selector/releases/download/v0.5.0/install.sh) into a new empty user-owned direct directory and deliberately select it. The [manual upgrade and recovery guide](manual-upgrade-recovery.md) separates executable selection, backups, migration, and recovery.

Interactive Codex is limited to the locked supported CLI, named ChatGPT identities, selected common capabilities, and declared workspace access. ACS does not expose arbitrary target arguments, remote MCP, plugins, hooks, agents, API-key import, backend choice, or generic Codex configuration passthrough. ACS has no background update checks, package-manager distribution, uninstaller, or network destination filter. Linux compilation is a non-blocking portability observation, not release evidence.

## Exact-byte and native evidence

The release workflow built one candidate and passed the same bytes to native validation, attestation, and publication. The public archive, manifest, and installer each match the run's candidate artifact `release-candidate-35796440099-1` byte-for-byte. The archive member `acs` has SHA-256 `f077d7bb4624a65e8e270df7ab3259d4289ad5410d6a49b53ebcae4c9f283fa5`. The [publication record](releases/v0.5.0-checklist.md#published-asset-identity) lists all three public asset hashes and sizes. GitHub attestation verification passed for the **archive and manifest**, bound to `release.yml`, `refs/tags/v0.5.0`, the final source commit, and run 35796440099/attempt 1. The installer is byte-matched to the run artifact but is not attested.

The native macOS 26 Apple Silicon job installed and exercised the release candidate bytes across normal, race, installed-artifact, containment, terminal, denial, lifecycle, recovery, and shared Devin/Codex gates. Its locked CI targets were Codex CLI/code-mode host 0.149.1 and Devin 3000.10.21, both `darwin/arm64`. Codex automation used synthetic authentication, a disposable Keychain, and a loopback simulated API. It verifies the contained test composition, not a real maintainer account, hosted inference, quota, refresh, or week-long use. The parallel macOS validation run also passed.

The release is intentionally unsigned and unnotarized. SHA-256 establishes byte identity against a trusted digest; attestation supplies provenance for its verified subjects. Neither supplies Apple Developer ID signing, notarization, malware review, or Gatekeeper approval. Do not remove quarantine, disable Gatekeeper, ad-hoc sign the binary, or weaken Seatbelt to make it run.

## Candidate and daily-use boundaries

The [historical candidate handoff](current-candidate-handoff.md) records the PR #118 development artifact, its embedded `v0.4.0` placeholder, and expired retention. Its bytes and run are not the published v0.5.0 package. A future promoted development candidate also needs its own source, artifact, digests, installed-byte, and native-result evidence. The [candidate migration and rollback guide](release-migration-guide.md) provides its operator procedure and a sanitized observation template; it is not the release asset download channel.

The release pipeline establishes final-tag build, native validation, attestation, and publication evidence. It does not establish the separate one-week observation of useful Devin and Codex work in two real project contexts. That observation is **UNPERFORMED / PENDING**. Keep issue #105 open until its own sanitized elapsed-use, account/hosted behavior, and cleanup evidence is recorded. Publication does not fill the template or imply the result.

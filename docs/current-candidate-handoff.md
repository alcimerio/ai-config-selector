# Historical unpublished candidate handoff

This is a sanitized identity and scope record for a historical development
candidate on macOS 26 Apple Silicon. It is not a release, a version decision, an
installed host observation, or evidence of real account use. Private downloads
and raw logs remain outside the repository. The
[release preparation](release-readiness.md) retains its original source
boundary; this page records the later tested tree.

The candidate's GitHub artifact retention expired on 2026-09-19. It is not the
current v0.5.0 development candidate and must not be presented as downloadable
or rebuilt under the old identity. A new candidate needs a new source/run,
artifact identity, complete digest set, installed-host measurement, and native
result. The facts below remain unchanged as historical evidence only.

## Source and artifact identity

| Item | Verified identity |
| --- | --- |
| Tested PR #118 head | `728305d929eefc32447f77b4d8f806d068cf9f0d` |
| CI synthetic merge source and parents | `e9b9f652178a1aa2eac80b042da6390ecb5d2b34` from `8afc0d0b060c524a29103d46c2f363d56330c6d3` and the PR head |
| Merged main commit | `49a427dbedc1e8b3b9490fac0262d183ebbf42f3` |
| Shared PR, CI and merged tree | `b7fb565eb4590f21a46464f6e9e22c3ecd2c828d` |
| Embedded development version | `acs v0.4.0`, the promoted workflow's placeholder; these are not published v0.4.0 bytes |
| Build and native run | [run 35371412640](https://github.com/alcimerio/ai-config-selector/actions/runs/35371412640), build job `105686016777` success, native macOS 26 `darwin/arm64` job `105686182030` success |
| Candidate artifact | ID `10558663258`, `acs-candidate-e9b9f652178a1aa2eac80b042da6390ecb5d2b34`, retention expiry `2026-09-19T16:56:57Z` |
| Downloaded artifact ZIP SHA-256 | `b5a29e89495aca52ec93fce830a4fb1a3f3b440ab8c1246a7a4ec908a645e9d9`, matching GitHub's artifact digest |
| `SHA256SUMS` SHA-256 | `a59e3bd894f582ee9796437eb876c6878c988961c79d007e4f9517acd1b7c37a` |
| `acs_0.4.0_darwin_arm64.tar.gz` SHA-256 | `e3f3c197d09bf144893d13a310511d1f283b1c6f73d2288a533867ddc27e995f`, matching `SHA256SUMS` |
| `install.sh` SHA-256 | `27ac17c112c990170cdb00d3a8a9a783cebb74ae845652d938c737bfd552a4d8` |
| Archive member `acs` SHA-256 | `0354f8fe0b19804215498c5749f89c4a21dd98473e15269b99b087f0c0d836c3`; expected installed byte identity, measured from the archive on Linux |
| Installed host SHA-256 | **Pending operator measurement** of the installed executable on macOS; the native log does not print this digest |

The ZIP contains exactly `SHA256SUMS`, `install.sh` and the named archive. The
archive contains `LICENSE`, `README.md` and executable `acs`. The saved ZIP's
GitHub digest, each extracted ZIP member, manifest check and archive structure
were independently checked without executing a Darwin binary on Linux. GitHub
commit metadata confirms the three tree identities above. The artifact retains
its actual CI source; a matching squash tree does not relabel its build commit.
Artifact expiry is a download deadline, not a lifetime for already retained
private bytes. The artifact ID and any GitHub download link are not a permanent
distribution channel; no `/tmp` capture path is part of the operator contract.

The native job used the supplied artifact through the existing installer and
then passed the shared installed candidate gates. It also passed the three
installed-discovery cases, selected and absent cases for both agent catalogs,
and three Devin hook repetitions. This proves bounded credential-free installed
operation, including the existing containment and lifecycle cases. It does not
supply an installed-file digest, real account use, hosted inference, or a week
of use.
The candidate is suitable for an operator evaluation once the Mac records the
installed-file digest and verifies it against the expected member digest.

The native target locks for this source are Codex CLI `0.149.1` arm64 archive
`ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405`,
Codex code mode host archive
`aae1c0c9459700a2e897adadd647351140ae7933ad73bd8d3af6505c69a4f3fd`,
and Devin `3000.10.21` arm64 archive
`c0b97f8197bf3ce895ff14aa19257c511154b49a0a195bba4962acb5e475c68e`.
These are target archive locks, not digests of installed target executables.

## Current-source release-note scope

Compared with immutable published v0.4.0, the current candidate includes the
previously prepared Profile v3, Codex, contained execution, explanation, local
history and Session operations described in [release readiness](release-readiness.md).
It also adds selected common instruction file references, verified Devin
always-on rule projection, bounded executable and path grants, scoped
attached-process-tree environment mappings, and reference-only local STDIO MCP
servers for Devin and Codex. The [instruction](instruction-bundles.md),
[common Profile](common-profile-format.md) and [MCP](mcp-profiles.md) guides
define their exact contracts.

The common instruction selections remain stored for both target overlays.
Only Devin materializes them as ACS-managed always-on rules and performs the
rule preflight. Codex's instruction projection is a no-op: this candidate does
not activate selected bundles as Codex rules. Ambient workspace instructions
remain target-owned.

Selected environment values are resolved at execution, not stored in Profiles,
exchange or history. Secret values can be read by the selected target, local MCP
server and descendants; they are not isolated per server. MCP argv values can
use selected non-secret environment and path references only. MCP tool filtering
is target behavior, not a containment guarantee. Generic `acs run` retains MCP
intent without launching a server. Devin's suppressed ambient import switches
also affect some target-owned rules and Skills. Review those effects before
using an existing Profile. Missing selected sources or required host environment
names fail rather than silently dropping requested capabilities.

PR #118 assessed plugins, hooks and agent definitions with contained target
fixtures. Those rows are assessment evidence only: this candidate adds no ACS
Profile schema or production activation path for them. Project-owned target
content can still be encountered within the selected workspace. This source
continues to support macOS 26 `darwin/arm64` with native Seatbelt. It does not
provide Intel or Linux release support, destination-specific network control,
arbitrary target configuration or an unsandboxed fallback. It is unsigned and
unnotarized; checksums and origin evidence do not establish Gatekeeper approval.

## Historical preservation procedure (retention expired)

Before `2026-09-19T16:56:57Z`, an authorized custodian could run the following in
a dedicated Bash from an operator-controlled Mac. Set `ACS_CANDIDATE_KEEP_DIR`
to a **new** absolute private directory outside a repository. The command uses
the custodian's existing GitHub CLI access to download the exact artifact ZIP;
it does not send the bytes to another service. It checks the ZIP before
extraction, requires the exact member list, then checks every extracted file and
the supplied archive manifest. A failed command stops before installation.

<!-- candidate-handoff-example: acquire -->
```sh
set -eu
umask 077
: "${ACS_CANDIDATE_KEEP_DIR:?set a new absolute private directory}"
case "$ACS_CANDIDATE_KEEP_DIR" in /*) ;; *) exit 1 ;; esac
test ! -e "$ACS_CANDIDATE_KEEP_DIR"
mkdir -m 700 "$ACS_CANDIDATE_KEEP_DIR"
keep_dir="$ACS_CANDIDATE_KEEP_DIR"
gh api repos/alcimerio/ai-config-selector/actions/artifacts/10558663258/zip \
  > "$keep_dir/artifact.zip"
printf '%s  %s\n' \
  b5a29e89495aca52ec93fce830a4fb1a3f3b440ab8c1246a7a4ec908a645e9d9 \
  "$keep_dir/artifact.zip" | shasum -a 256 -c -
unzip -Z -1 "$keep_dir/artifact.zip" > "$keep_dir/members.txt"
printf '%s\n' SHA256SUMS acs_0.4.0_darwin_arm64.tar.gz install.sh \
  > "$keep_dir/expected-members.txt"
cmp "$keep_dir/expected-members.txt" "$keep_dir/members.txt"
mkdir -m 700 "$keep_dir/files"
unzip -q "$keep_dir/artifact.zip" -d "$keep_dir/files"
cat > "$keep_dir/expected.sha256" <<'SHA256'
a59e3bd894f582ee9796437eb876c6878c988961c79d007e4f9517acd1b7c37a  SHA256SUMS
e3f3c197d09bf144893d13a310511d1f283b1c6f73d2288a533867ddc27e995f  acs_0.4.0_darwin_arm64.tar.gz
27ac17c112c990170cdb00d3a8a9a783cebb74ae845652d938c737bfd552a4d8  install.sh
SHA256
(
  cd "$keep_dir/files"
  shasum -a 256 -c "$keep_dir/expected.sha256"
  shasum -a 256 -c SHA256SUMS
)
```

Retain `artifact.zip`, the extracted `files` directory, `expected.sha256`, and
the member lists as the private operator copy. Repeat the digest and manifest
checks after any transfer. The ZIP digest fixes the checked archive structure:
independent inspection found exactly `LICENSE`, `README.md` and executable
`acs` inside it, with the member digest in the table above. On the Mac, use the
[migration guide](release-migration-guide.md) to validate the artifact set,
install into a private maintenance directory and check the installed executable's
digest and version. Retain that Mac result as a distinct installed-host witness.
Any mismatch stops the handoff before installation or Profile changes.

If the GitHub artifact has expired or cannot be downloaded, use a privately
retained copy only if the original ZIP and all extracted bytes pass those same
checks. If no verified copy exists, stop. Build a **new** candidate with the
existing promoted artifact workflow from an explicitly reviewed source commit,
record its new source tree, run and job IDs, artifact ID, retention, and all new
digests, and require its native validation to finish successfully. Never assign
the old artifact ID or digests to rebuilt bytes, and never claim the new run
inherits the previous native result. The operator must receive and verify that
new identity before starting the evaluation.

## Historical operator sequence and pending decisions

1. Obtain the candidate through the private handoff and complete the preservation
   and verification procedure above.
2. Use a clean checkout of merged commit
   `49a427dbedc1e8b3b9490fac0262d183ebbf42f3` for the existing
   [candidate migration and rollback procedure](release-migration-guide.md).
   Its tree is identical to the CI source. Record both the actual CI source and
   the matching checkout commit. Validate, install and hash the installed
   executable on macOS; record its SHA-256 separately from the archive member.
3. Check the Profile's selected instructions, paths, executables, environment
   references and MCP declarations before any migration or write. Keep the
   known-good executable and a compatible candidate available for newer state
   recovery. Binary rollback never downgrades stored data.
4. The guide's two-project, one-week Devin and Codex observation remained
   unperformed for this candidate. Any later observation must use its actual
   candidate identity, aliases, and public result categories only. Real-account
   access and elapsed time are pending operator actions, not CI results. Record
   failures and recovery without credential values, target output or private
   paths.
5. This historical candidate does not authorize or supply the v0.5.0 release
   cut. A future tag run builds different, versioned bytes and must establish
   its own native and attestation evidence. The v0.5.0 release preparation uses
   an approved unsigned/unnotarized posture; the daily-use observation remains
   a separate pending milestone. Do not close the release or daily-use issues
   from this candidate preparation alone. [Release preparation #102](https://github.com/alcimerio/ai-config-selector/issues/102),
   [exact artifact #103](https://github.com/alcimerio/ai-config-selector/issues/103),
   [migration #104](https://github.com/alcimerio/ai-config-selector/issues/104)
   and [daily use #105](https://github.com/alcimerio/ai-config-selector/issues/105)
   retain their separate acceptance criteria.

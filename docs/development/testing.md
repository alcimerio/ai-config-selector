# Testing and dependency maintenance

[Documentation index](../README.md) · [Contributing](../../CONTRIBUTING.md) · [Release procedure](releasing.md)

Run the normal and race suites in [local setup](../../CONTRIBUTING.md#local-setup)
on macOS 26 Apple Silicon. Native tests require a normal terminal; another
restrictive sandbox can invalidate their results. Never weaken macOS security
settings to make a test pass.

## Testing the sandbox shell

The shell must remain `/bin/zsh -f`. Cover selected Skills, clean environment
and descriptors, workspace/Session writes, unrelated-path and symlink denial,
absence of Devin credentials/preflights, terminal I/O, resize, signals, exit
status, descendant settlement and stable fail-closed errors on every exit path.

```sh
go test ./internal/launch ./internal/sandboxshell -count=1
go test -race ./internal/launch ./internal/sandboxshell -count=1
```

For cross-target capability and lifecycle checks, use
[shared target conformance](../reference/shared-target-conformance.md#testing-compatibility-changes).

## Portable source checks

OS-specific filesystem and terminal shims keep shared code testable on Linux.
The `Portable Linux tests` CI job on `ubuntu-24.04` checks formatting, vets
linux/amd64 and darwin/arm64, builds linux/amd64 and linux/arm64, runs
`go test ./...`, and confirms that a Linux launch fails closed because no Linux
backend exists yet. To compile without running anything, use `go test -c`, not
`go test -run '^$'`, which starts test executables and package initialization. Portable unit tests supplement
native checks; they establish neither Linux runtime support nor containment.

The [Staticcheck helper](../../scripts/check-go-staticcheck.sh) runs the same
pinned checker as CI, including tests, for both source targets:

```sh
scripts/check-go-staticcheck.sh linux amd64
scripts/check-go-staticcheck.sh darwin arm64
```

It builds the checker for the host with the project's selected Go toolchain,
then applies the analysis target. Version-suffixed `go run` ignores the local
`go.mod`, so the helper resolves the toolchain before invoking it. A separately
installed Staticcheck may have been built with an older Go version or export-data
reader and fail to analyze the project even when `go test` succeeds. Review the
checker pin when upgrading Go; keep both target checks and test analysis enabled.

## Native named-authentication evidence

The promoted-artifact workflow fetches both [reviewed target pairs](../reference/target-compatibility.md)
once, verifies their SHA-256 locks and installs each CLI with its matching sibling
on macOS 26. The native matrix tests each exact version against the same supplied
ACS candidate. Credential-free native tests use real Seatbelt, a disposable Keychain
and synthetic home, without account credentials or captured private content.

On pull requests and main, the native matrix sets
`ACS_NATIVE_BROAD_SUITES=covered-by-macos-verify`, so it does not repeat the
unfiltered `go test -v ./...` and `go test -race ./...` suites: the required
Verify (macOS) check runs them on the same commit as parallel unit and race
jobs. The tag release workflow never sets it and always runs both suites inside
the shared native gate.

For a local run:

1. Fetch and install the locked target with `scripts/fetch-codex-test-targets.sh`
   and `scripts/install-codex-test-target.sh`.
2. Set `ACS_RUN_NATIVE_AUTH_GATE=1`, `ACS_TEST_CODEX_BINARY` to that verified
   installation, and `ACS_NATIVE_AUTH_RECOVERY_ROOT` to a deterministic private path.
3. Run the focused tests and then the separate `TestNativeKeychainRecoveryEntrypoint`
   invocation, even if the first invocation fails. See
   [the shared native gate](../../scripts/run-native-candidate-gates.sh) for exact commands.

The shared gate runs recovery in its exit/signal trap. Hard runner termination
can prevent the trap; preserve private recovery evidence when cleanup was not
observed. This gate proves the isolated Keychain contract and contained status
lifecycle, not interactive login completion or target-origin token refresh.
Synthetic login must be rejected as unverified; subsequent status and sandbox
checks use test identities verified with injected signing keys and seeded in
the disposable Keychain.
Production queries prohibit authentication UI. Deterministic tests cover locked
or unavailable providers; live locked-Keychain and direct ACL probes remain
supplemental because macOS can present access-control UI.

## Native filesystem exclusion evidence

The shared candidate gate runs focused integrated exclusion checks. Generic
commands exercise denied reads, writes, creation, listing, rename, unlink,
replacement, symlink aliases and child processes in both workspace modes, while
allowed neighbors remain usable. The locked Devin target checks single-bundle
and whole-root catalog omission. Each reviewed Codex pair also exercises real
catalog discovery through the registered ACS recipe, a fixed app-server
trampoline, synthetic identity and disposable Keychain. These checks send no
model request and use no account credentials. They establish catalog and native
pathname enforcement, not model behavior, content-wide secrecy or disappearance
of excluded names from parent listings.

## Optional authenticated smoke

Authenticated Devin and Codex checks are supplemental observations. They must
not run in CI, use a shared account or replace the credential-free native gate.
Use a trusted supported Mac and normal terminal, with recording, shell tracing,
debug logging and output capture disabled. Install the exact reviewed candidate
using the [candidate procedure](releasing.md#test-a-development-candidate) and
verified, locked target binaries.

- **Devin:** use an already authenticated CLI. Observe sandbox, Skill/authentication
  preflight, interactive lifecycle, return to the terminal and no leased Session
  after exit. A Profile launch may copy its existing credential into the Session.
- **Codex:** use a dedicated test account and clean disposable identity name.
  Run browser/device login, then contained status. Observe target-origin token
  refresh only if it happens naturally; never force, inject, copy, decode,
  compare or print tokens. Use ACS logout and check for leased Sessions/quarantine.

If cleanup is uncertain, retain the compatible binary and private evidence and
follow [manual recovery](../guides/manual-upgrade-recovery.md). Do not delete
Session/Keychain state, bypass quarantine with logout, copy global Codex auth,
weaken Seatbelt or bypass a native trust failure.

Record only source commit, artifact/installed-binary digests, locked target
version/digest, host architecture, command category and pass/fail or not observed.
Account identifiers, device codes, browser URLs, target output, credentials,
token timestamps, Keychain contents, homes, Sessions, private paths, environment
values and generated policy must not be recorded. Record actual duration and
scope for separate daily-use observations; never infer it from automated or
publication success. A smoke does not prove reproducibility, release immutability
or deterministic account behavior.

## Research harnesses

Extension/hook fixtures use synthetic authentication and local simulators.
Run portable fixtures with `go test ./internal/extensionassessment`. The
[promoted-artifact workflow](../../.github/workflows/promoted-artifacts.yml) has
an opt-in locked-target `TestPromotedArtifactNativeDevinSessionStartHook` check;
keep it separate from mandatory release gates and use no account credentials.
These probes do not activate ACS-managed extensions or prove hosted inference
or detached-child cleanup beyond their tested containment contract.

The [macOS Session benchmark](../../.github/workflows/macos-session-benchmark.yml)
is dispatched manually only (`gh workflow run macos-session-benchmark.yml -f ref=main
-f iterations=10 [-f compare_ref=<ref>]`). It builds `acs` from the chosen refs
and runs real Seatbelt `acs devin` Sessions with `ACS_DEBUG_TIMING=1` against
the synthetic target in [`tools/sessionbench`](../../tools/sessionbench), which
needs no account, credential or network access. Variants select one Skill
bundle with 0 or 20 extra files. The job summary lists median and p90 per phase,
and the raw JSON Lines and CSV are uploaded as an artifact. Numbers come from a
shared CI runner: compare refs within one run rather than across runs.

[Native transport probes](native-transport-research.md) use a disposable macOS
runner. Their evidence does not change runtime policy or establish destination
filtering. Keep research evidence separate from production feature claims.

## Dependency maintenance and vulnerability checks

[Dependabot](../../.github/dependabot.yml) checks Go modules and Actions weekly,
grouping minor/patch updates per ecosystem and leaving majors separate. Review
updates through existing native gates; there is no automatic merge. Pin Actions
to full commit SHAs.

The sole exception is `github.com/charmbracelet/x/vt` at exact `= v0.1.0`: the
parent repository tag is not a valid `vt/v0.1.0` submodule tag. Bare version
syntax excludes a wider range. Review the exception when upstream gains real
tags; check `go list -m -json github.com/charmbracelet/x/vt@latest` for newer
pseudo-versions that Dependabot may miss. The selected pseudo-version remains
covered by vulnerability scanning.

[The vulnerability workflow](../../.github/workflows/vulnerabilities.yml) runs
on PRs, main pushes, weekly and manually. Release and promoted-artifact workflows
scan source before build and the exact installed candidate before native gates;
attestation/publication require success. These checks do not rebuild the candidate.

[The scanner helper](../../scripts/check-go-vulnerabilities.sh) pins a
`govulncheck` source commit and uses the exact Go version in `go.mod`. Review the
scanner pin when upgrading Go; Dependabot does not update it. The helper installs
in a disposable directory for the host, ignoring inherited cross-compilation
settings. Source analysis uses `darwin/arm64`, `CGO_ENABLED=0`, including tests,
without executing them. Binary analysis reads the supplied installed file and
checks that its SHA-256 stayed unchanged, without executing or rebuilding ACS.

```sh
scripts/check-go-vulnerabilities.sh source
scripts/check-go-vulnerabilities.sh binary /absolute/path/to/installed/acs
```

The scanner is pinned; the public `https://vuln.go.dev` database is live. Text and
version output record scanner, Go and database metadata. Reachable source findings,
binary findings and scanner/database errors block promotion. JSON/SARIF-only
output can succeed with findings and must not replace the gate.

Source analysis reports reachable symbols, including test paths; review verbose
module/package findings separately. Binary analysis cannot establish source call
paths and may report unreachable symbols. If symbols are unavailable, including
stripped artifacts, it falls back to module-level advisory matches. Those also
block the gate without proving each function callable. See
[govulncheck limitations](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck#hdr-Limitations).

Fix affected dependencies or Go; do not bypass findings or add arbitrary
exclusions. A pass is point-in-time evidence, not a complete graph audit or
coverage of Actions, target binaries or unknown vulnerabilities. Dependabot
version updates do not enable or prove access to GitHub alerts/security updates;
the public Go scan needs no GitHub alert access.

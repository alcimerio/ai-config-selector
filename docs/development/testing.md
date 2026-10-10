# Testing and dependency maintenance

[Documentation index](../README.md) · [Contributing](../../CONTRIBUTING.md) · [Release procedure](releasing.md)

Run the normal and race suites in [local setup](../../CONTRIBUTING.md#local-setup)
on macOS 26 Apple Silicon. Native tests require a normal terminal; another
restrictive sandbox can invalidate their results. Never weaken macOS security
settings to make a test pass.

## Testing the sandbox shell

The macOS shell must remain `/bin/zsh -f`. Cover selected Skills, clean environment
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

Run the same Staticcheck gates as CI with:

```sh
scripts/check-go-staticcheck.sh linux amd64
scripts/check-go-staticcheck.sh darwin arm64
```

The helper builds the pinned analyzer with the exact Go version in `go.mod`
and explicitly includes tests when checking the requested target. It analyzes
test code without executing target binaries, so either gate can run on Linux
or macOS. Use it instead of an
older installed `staticcheck`: both the analyzer's Go version and its export-data
reader must support the module's toolchain. A bare versioned `go run` can select
the analyzer's older minimum Go version even inside this repository.

### Linux capability probes

`go test -v ./internal/linuxprobe` runs mocked failure gates plus native ABI,
namespace, seccomp, cgroup and system-Bubblewrap observations. Native tests skip
with a specific prerequisite reason only when `ACS_LINUX_NATIVE_REQUIRED` is
unset. On a qualification host, use:

```sh
ACS_LINUX_NATIVE_REQUIRED=1 CGO_ENABLED=0 go test -v ./internal/linuxprobe -count=1
```

With the variable set, unavailable prerequisites fail the suite. Do not count
skips as native evidence. The initial host target is Ubuntu 24.04 HWE on amd64,
kernel 6.12+, Landlock ABI 6+, working unprivileged user/mount/PID namespaces,
seccomp, trusted `/usr/bin/bwrap`, and an owned delegated cgroup v2 domain.
The probe temporarily creates one child cgroup and kills/reaps its fixed helper;
it does not allocate an ACS Session. Landlock ABI availability and a probe
seccomp filter do not establish the full containment contract. Linux production
launch admission stays disabled. See the [diagnostic probe scope](../guides/diagnostics.md#experimental-linux-capability-probes).

### Native Linux containment CI (roadmap item 14)

The separate [Native Linux workflow](../../.github/workflows/linux-native.yml)
runs on `ubuntu-24.04` amd64 with `ACS_LINUX_NATIVE_REQUIRED=1` and
`CGO_ENABLED=0`. It records `uname`, the Landlock ABI, user/mount/PID namespace
sysctls (including `kernel.apparmor_restrict_unprivileged_userns`), AppArmor/LSM
observations, and cgroup membership, ownership and controls before setup.
The read-only `TestNativeLinuxHostEvidence` can pass on an unsuitable host;
only the subsequent mandatory probes establish prerequisites.

[The gate script](../../scripts/run-linux-native-gates.sh) requests
`systemd-run --user --scope --property=Delegate=yes` and records evidence again
inside that scope. It requires kernel 6.12+, Ubuntu 24.04, Landlock ABI 6+,
unprivileged user/mount/PID namespaces, seccomp, trusted system `/usr/bin/bwrap`,
and an owned delegated cgroup v2 domain. The cgroup probe must place and kill a
helper, prove empty membership and remove its child. WSL and containers are
rejected. Missing delegation, old kernels and any other missing prerequisite
**fail the job**; there is no successful skip or weaker fallback.

After prerequisites pass, the script installs checksum-locked Linux Devin and
both reviewed Codex CLI/companion pairs without running them uncontained. It
runs the Linux probe, launch, file-provider and executor suites. Every selected
test, including subtests, must avoid skips, and the named containment and denial
tests must report a pass; an empty or renamed suite cannot qualify the platform.
Job logs include host evidence and failures; per-suite logs remain in
`$RUNNER_TEMP/acs-linux-native/*.log` for the job's lifetime. No account
credentials are used.

If a Session supervisor exits before the readiness byte `R`, the assertion now
includes its exit status, captured stderr/stdout and failing setup stage. This
also includes Bubblewrap/contained-init logs (or PTY output for interactive
cases). `TestLinuxNativeSessionCgroupStartup` checks that the kill preflight
leaves a fresh cgroup that can start a helper, then verifies kill and settlement.
See the [Linux 6.17 startup investigation](../design/linux-session-containment.md#ownership-and-start-gate).

The hosted runner's mutable kernel and user-manager delegation have **not been
qualified**. Keep `Native Linux containment (amd64, qualification pending)`
**out of required branch-protection checks** while this gap remains. Its failure
must stay visible rather than using `continue-on-error`, ignoring test status,
or globally disabling AppArmor's userns restrictions. If the hosted runner
cannot satisfy the floor or delegation, provision a dedicated ephemeral
self-hosted amd64 runner, or a native amd64 Ubuntu 24.04 HWE VM on a host with
nested virtualization. Boot kernel 6.12+ with Landlock enabled, install system
Bubblewrap with an appropriate AppArmor profile, and provision the runner user's
systemd manager and `Delegate=yes` scope (or a reviewed delegated domain slice).
Run the same gate and retain its real evidence before promoting the check to
required status. Do not substitute a container or run the tests as root.

The native assertions cover filesystem/syscall denials and allowed controls,
TTY input restoration, fork/setsid containment, owner/supervisor loss,
authenticated cleanup and credential-free target preflights. Provider lifecycle
and failure-injection fixtures also run, but their modeled settlement is not
independent native process proof. This job is a normal, static Go build; it
does not claim race-instrumented native evidence. The existing macOS normal,
race and release gates remain separate and unchanged. Production Linux launch
admission and Linux release publication remain disabled pending the remaining
qualification and activation work.

### Native arm64 deferred (roadmap item 15)

Linux arm64 remains unsupported and unpublished until a **native arm64** runner
passes the same containment, denial, terminal, target and cleanup gates, together
with the minimum/disabled-feature and filesystem qualification matrix. The
portable arm64 cross-build is compilation evidence only. QEMU or other emulator
results do not count as native evidence and cannot close item 15.

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

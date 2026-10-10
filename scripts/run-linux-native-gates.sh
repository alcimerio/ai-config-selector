#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export ACS_LINUX_NATIVE_REQUIRED=1
export CGO_ENABLED=0

fail() {
  printf 'native Linux gate: %s\n' "$1" >&2
  exit 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  fail 'usage: bash scripts/run-linux-native-gates.sh <absolute-evidence-directory>'
fi
gate_root=$1
[[ $gate_root == /* ]] || fail 'evidence directory must be absolute'
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cd -- "$script_dir/.."

if [[ $# == 1 ]]; then
  mkdir -m 0700 -- "$gate_root"
  command -v systemd-run >/dev/null || fail 'systemd-run is unavailable; owned cgroup v2 delegation is required'
  # A scope preserves the caller's environment and working directory. Do not
  # sudo the tests, move unrelated processes, or chown systemd-owned cgroups.
  if systemd-run --user --scope --property=Delegate=yes --quiet \
    bash "$script_dir/run-linux-native-gates.sh" "$gate_root" --delegated; then
    exit 0
  fi
  fail 'delegated native qualification failed; inspect kernel/feature evidence above. Use a qualified Ubuntu 24.04 HWE amd64 host or nested-virt VM; do not require this check in branch protection yet'
fi
[[ $2 == --delegated ]] || fail 'unknown gate mode'
[[ -d $gate_root && ! -L $gate_root ]] || fail 'evidence directory is unavailable or unsafe'

run_suite() {
  local label=$1 package=$2 pattern=$3
  shift 3
  local log="$gate_root/$label.log" test_name
  # pipefail preserves go test's status even though tee records the evidence.
  if ! go test -v -count=1 -timeout=15m "$package" -run "$pattern" 2>&1 | tee "$log"; then
    fail "$label suite failed; see $log"
  fi
  if grep -Eq '^[[:space:]]*--- SKIP:' "$log"; then
    fail "$label suite skipped an assertion; native qualification requires every selected test"
  fi
  for test_name in "$@"; do
    if ! grep -Eq "^--- PASS: $test_name [(]" "$log"; then
      fail "$label suite did not pass required test $test_name (missing tests are not evidence)"
    fi
  done
}

# Record the scope's actual membership and ownership as well as the initial
# runner evidence. A successful systemd-run alone does not prove delegation.
run_suite prerequisites ./internal/linuxprobe '^TestNative' \
  TestNativeLinuxHostEvidence TestNativeLinuxPrerequisites \
  TestNativeLandlockABI TestNativeUserNamespaces TestNativeSeccomp \
  TestNativeCgroupDelegation TestNativeSystemBwrapIdentity TestNativeRequiredModeRejectsSkipping

# Fetch only after the actual kernel, userns, Landlock, seccomp, bwrap provenance
# and cgroup placement/kill/empty/removal probes pass. Installers verify bytes
# and never execute Linux targets outside the test-only containment harness.
mkdir -m 0700 -- "$gate_root/devin" "$gate_root/codex"
bash scripts/install-devin-test-target.sh scripts/devin-test-targets.lock \
  "$gate_root/devin" "$gate_root/devin/devin"
bash scripts/fetch-codex-test-targets.sh scripts/codex-linux-test-targets.lock "$gate_root/codex-archives"
for version in 0.149.1 0.156.0; do
  mkdir -m 0700 -- "$gate_root/codex/$version"
  bash scripts/install-codex-test-target.sh scripts/codex-linux-test-targets.lock \
    "$gate_root/codex-archives" amd64 "$gate_root/codex/$version/codex" "$version"
done
export ACS_TEST_DEVIN_BINARY="$gate_root/devin/devin"
export ACS_TEST_CODEX_LINUX_ROOT="$gate_root/codex"

run_suite containment ./internal/launch '^TestLinux' \
  TestLinuxNativeRestrictionControls TestLinuxNativeSetupFailuresNeverExec \
  TestLinuxNativeBwrapComposition TestLinuxNativePidfdDoesNotSignalUnrelatedProcess \
  TestLinuxNativeContainedInitGateSignalsAndExit TestLinuxNativeMissingDelegationRefusesAllocation \
  TestLinuxNativeSessionContainment TestLinuxNativeCleanupRestoresTTYAndFlushesPendingInput \
  TestLinuxNativeRecipeStartupAndLiteralArguments TestLinuxNativeRecipeInteractiveShell \
  TestLinuxNativeRecipeComposition TestLinuxDevinPublishedBytes TestLinuxNativeDevinPreflights \
  TestLinuxCodexPublishedPairs TestLinuxNativeCodexPairs \
  TestLinuxHasNoSandboxBackend TestLinuxSandboxFailsClosed
run_suite credentials ./internal/codexauthresource '^TestLinux' \
  TestLinuxFileProviderConformance TestLinuxFileProviderRequiresDurableOptIn \
  TestLinuxFileProviderStoreRefreshAndQuarantine TestLinuxFileProviderRecoveryRefresh \
  TestLinuxFileProviderCommitsLoginOnlyAfterSettlement
run_suite executor ./internal/executor '^TestLinux' \
  TestLinuxLaunchFailsBeforeSessionCreation TestLinuxDevinProjectsOnlyTheAllowlistedCredential \
  TestLinuxCodexFileProviderLifecycle TestLinuxCodexNeverFallsBackToGlobalAuth

printf '%s\n' 'Native Linux suites passed with mandatory prerequisites and no skipped selected tests. Production Linux launches remain disabled.'

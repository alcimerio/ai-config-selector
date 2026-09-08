#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 6 ]; then
  printf '%s\n' "usage: scripts/run-native-candidate-gates.sh <candidate-version> <candidate-binary> <codex-binary> <codex-archive> <recovery-root> <sandbox-backend>" >&2
  exit 2
fi

candidate_version="$1"
candidate_binary="$2"
codex_binary="$3"
codex_archive="$4"
recovery_root="$5"
sandbox_backend="$6"

fail() {
  printf 'run native candidate gates: %s\n' "$1" >&2
  exit 1
}

[ -n "$candidate_version" ] || fail "candidate version is required"
case "$candidate_binary:$codex_binary:$codex_archive:$recovery_root" in
  /*:/*:/*:/*) ;;
  *) fail "candidate, target, archive and recovery paths must be absolute" ;;
esac
[ -f "$candidate_binary" ] && [ ! -L "$candidate_binary" ] && [ -x "$candidate_binary" ] || fail "supplied candidate binary is unavailable or unsafe"
[ -f "$codex_binary" ] && [ ! -L "$codex_binary" ] && [ -x "$codex_binary" ] || fail "supplied Codex binary is unavailable or unsafe"
[ -f "$codex_archive" ] && [ ! -L "$codex_archive" ] || fail "supplied Codex archive is unavailable or unsafe"
[ "$sandbox_backend" = "available" ] || fail "native sandbox backend must be available"

# The caller supplies these values as positional inputs. Do not let ambient
# fixture flags broaden the unfiltered source and race suites.
unset ACS_PROMOTED_VERSION ACS_PROMOTED_BINARY ACS_PROMOTED_SANDBOX_BACKEND
unset ACS_RUN_NATIVE_AUTH_GATE ACS_RUN_NATIVE_AUTH_RECOVERY
unset ACS_NATIVE_AUTH_RECOVERY_ROOT ACS_TEST_CODEX_BINARY ACS_TEST_CODEX_ARCHIVE

read_digest() {
  digest_output="$(shasum -a 256 "$1")" || return 1
  read_digest_value="${digest_output%% *}"
  [ "${#read_digest_value}" -eq 64 ] || return 1
  case "$read_digest_value" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

read_digest "$candidate_binary" || fail "candidate identity could not be read"
candidate_digest="$read_digest_value"
read_digest "$codex_binary" || fail "Codex identity could not be read"
codex_digest="$read_digest_value"
read_digest "$codex_archive" || fail "Codex archive identity could not be read"
archive_digest="$read_digest_value"

run_auth_test() {
  ACS_PROMOTED_BINARY="$candidate_binary" \
  ACS_RUN_NATIVE_AUTH_GATE=1 \
  ACS_NATIVE_AUTH_RECOVERY_ROOT="$recovery_root" \
  ACS_TEST_CODEX_BINARY="$codex_binary" \
  ACS_TEST_CODEX_ARCHIVE="$codex_archive" \
    go test "$@"
}

run_acceptance_test() {
  ACS_PROMOTED_VERSION="$candidate_version" \
  ACS_PROMOTED_BINARY="$candidate_binary" \
  ACS_PROMOTED_SANDBOX_BACKEND="$sandbox_backend" \
    go test "$@"
}

require_test() {
  package="$1"
  test_name="$2"
  listed="$(go test "$package" -list "^${test_name}$")" || fail "required test discovery failed"
  printf '%s\n' "$listed" | grep -qx "$test_name" || fail "required test $test_name is unavailable"
}

finish() {
  primary_status=$?
  trap - EXIT HUP INT TERM
  set +e

  ACS_RUN_NATIVE_AUTH_RECOVERY=1 \
  ACS_NATIVE_AUTH_RECOVERY_ROOT="$recovery_root" \
    go test ./internal/codexauthresource -run '^TestNativeKeychainRecoveryEntrypoint$' -count=1
  recovery_status=$?

  identity_status=0
  if ! read_digest "$candidate_binary" || [ "$read_digest_value" != "$candidate_digest" ]; then
    identity_status=1
  fi
  if ! read_digest "$codex_binary" || [ "$read_digest_value" != "$codex_digest" ]; then
    identity_status=1
  fi
  if ! read_digest "$codex_archive" || [ "$read_digest_value" != "$archive_digest" ]; then
    identity_status=1
  fi
  if [ "$identity_status" -ne 0 ]; then
    printf '%s\n' "run native candidate gates: supplied artifact identity changed during validation" >&2
  fi

  if [ "$primary_status" -ne 0 ]; then
    exit "$primary_status"
  fi
  if [ "$recovery_status" -ne 0 ]; then
    printf '%s\n' "run native candidate gates: native authentication recovery failed" >&2
    exit "$recovery_status"
  fi
  exit "$identity_status"
}
handle_signal() {
  signal_status="$1"
  trap - HUP INT TERM
  exit "$signal_status"
}
require_test ./internal/codexauthresource TestNativeKeychainRecoveryEntrypoint
trap finish EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

require_test ./internal/codexauthresource TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity
run_auth_test ./internal/codexauthresource -run '^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$' -count=1 -v

# These broad suites deliberately remain unfiltered so new restoration, Session
# recovery and installed-artifact coverage enters the release gate automatically.
scripts/run-bounded-test-command.sh 420 go test -count=1 -v -timeout=6m ./...

require_test ./acceptance TestPromotedArtifactSharedTargetConformance
run_acceptance_test ./acceptance -run '^TestPromotedArtifactSharedTargetConformance$' -count=1 -v
require_test ./acceptance TestPromotedArtifactNativeContainmentContract
run_acceptance_test ./acceptance -run '^TestPromotedArtifactNativeContainmentContract$/^generic_literal_command_uses_candidate_containment$' -count=1 -v
run_acceptance_test ./acceptance -run '^TestPromotedArtifactNativeContainmentContract$/^effective_explanation_is_linked_and_narrowly_observed$' -count=1 -v

scripts/run-bounded-test-command.sh 420 go test -count=1 -v -timeout=6m -race ./...

require_test ./internal/profilerepo TestNativeVolumeAliasPolicy
require_test ./internal/profilerepo TestIndependentWritersAndLiveKernelOwnership
require_test ./internal/profilerepo TestRestrictedIdentityPermissionDenial
go test ./internal/profilerepo -run '^(TestNativeVolumeAliasPolicy|TestIndependentWritersAndLiveKernelOwnership|TestRestrictedIdentityPermissionDenial)$' -count=1 -v

# Each disposable Keychain gets a fresh process for native framework state.
require_test ./internal/codexauthresource TestNativeKeychainCredentialFreeContract
run_auth_test ./internal/codexauthresource -run '^TestNativeKeychainCredentialFreeContract$' -count=1
require_test ./internal/codexauthresource TestNativeRealStoreInstalledTargetComposition
run_auth_test ./internal/codexauthresource -run '^TestNativeRealStoreInstalledTargetComposition$' -count=1 -v
require_test ./internal/executor TestNativeInstalledTargetContainedStatusWithoutCredentials
run_auth_test ./internal/executor -run '^TestNativeInstalledTargetContainedStatusWithoutCredentials$' -count=1
require_test ./internal/executor TestNativeDirectInstalledTargetInteractiveLifecycle
run_auth_test ./internal/executor -run '^TestNativeDirectInstalledTargetInteractiveLifecycle$' -count=1 -v

run_acceptance_test ./acceptance -count=1

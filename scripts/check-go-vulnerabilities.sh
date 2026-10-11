#!/bin/sh

# One scanner pin and one fail-closed policy for PR, scheduled and tag gates.
set -eu
set -f
LC_ALL=C
export LC_ALL

fail() {
  printf 'Go vulnerability gate: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf '%s\n' 'usage: scripts/check-go-vulnerabilities.sh source | binary <absolute-installed-candidate>' >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
mode="$1"
case "$mode" in
  source) [ "$#" -eq 1 ] || usage ;;
  binary)
    [ "$#" -eq 2 ] || usage
    candidate_binary="$2"
    case "$candidate_binary" in /*) ;; *) fail "candidate path must be absolute" ;; esac
    [ -f "$candidate_binary" ] && [ ! -L "$candidate_binary" ] && [ -x "$candidate_binary" ] || fail "installed candidate is unavailable or unsafe"
    ;;
  *) usage ;;
esac

read_candidate_digest() {
  [ -f "$candidate_binary" ] && [ ! -L "$candidate_binary" ] && [ -x "$candidate_binary" ] || return 1
  digest_output="$(shasum -a 256 "$candidate_binary")" || return 1
  candidate_digest_value="${digest_output%% *}"
  [ "${#candidate_digest_value}" -eq 64 ] || return 1
  case "$candidate_digest_value" in *[!0-9a-f]*) return 1 ;; esac
}

if [ "$mode" = binary ]; then
  read_candidate_digest || fail "candidate identity could not be read"
  candidate_digest="$candidate_digest_value"
fi

script_directory="$(CDPATH= cd "$(dirname "$0")" && pwd -P)" || fail "script location could not be resolved"
cd "$(dirname "$script_directory")" || fail "repository directory could not be opened"

# Build the scanner for the host even if the caller is cross-compiling ACS.
# Do not inherit persistent Go settings, a claimed Go version, an alternate
# workspace, build tags, package-loading driver, scanner or database.
unset GOOS GOARCH CGO_ENABLED GOVERSION GOVULNDB GOVULNCHECK
GOTOOLCHAIN=local
GOFLAGS=
GOWORK=off
GOENV=off
GOPACKAGESDRIVER=off
export GOTOOLCHAIN GOFLAGS GOWORK GOENV GOPACKAGESDRIVER

workspace="$(mktemp -d "${TMPDIR:-/tmp}/acs-govulncheck.XXXXXX")" || fail "scanner workspace could not be created"
cleanup() {
  rm -rf "$workspace"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# golang.org/x/vuln v1.8.0. Review this immutable source pin with Go upgrades.
readonly scanner_source='golang.org/x/vuln/cmd/govulncheck@709015412431dd2b5b28a53c06c70bc02d49074c'
printf 'Go vulnerability gate: mode=%s scanner=%s database=https://vuln.go.dev\n' "$mode" "$scanner_source"
GOBIN="$workspace" go install "$scanner_source"
scanner="$workspace/govulncheck"
[ -f "$scanner" ] && [ ! -L "$scanner" ] && [ -x "$scanner" ] || fail "pinned scanner is unavailable or unsafe"

# Text output preserves nonzero findings and analysis/database errors. Version
# output records the scanner, Go version and live database's last-modified time.
# JSON/SARIF alone can exit successfully despite findings and are not gates.
if [ "$mode" = source ]; then
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
    "$scanner" -test -show=verbose,version -format=text -db=https://vuln.go.dev ./...
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    "$scanner" -test -show=verbose,version -format=text -db=https://vuln.go.dev ./...
else
  scan_status=0
  "$scanner" -mode=binary -show=verbose,version -format=text -db=https://vuln.go.dev "$candidate_binary" || scan_status=$?
  identity_status=0
  if ! read_candidate_digest || [ "$candidate_digest_value" != "$candidate_digest" ]; then
    printf '%s\n' 'Go vulnerability gate: candidate identity changed during vulnerability scan' >&2
    identity_status=1
  fi
  # Never hide the primary finding/error behind a subsequent identity check.
  [ "$scan_status" -eq 0 ] || exit "$scan_status"
  [ "$identity_status" -eq 0 ] || exit "$identity_status"
  printf 'Go vulnerability gate: installed candidate SHA-256=%s\n' "$candidate_digest"
fi

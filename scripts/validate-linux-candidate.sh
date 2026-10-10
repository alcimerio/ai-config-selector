#!/bin/sh

# Packaging evidence only. This does not exercise or admit a Linux sandbox.
set -eu
set -f
LC_ALL=C
export LC_ALL

fail() { printf 'Linux candidate validation failed: %s\n' "$1" >&2; exit 1; }
[ "$#" -eq 3 ] || fail "expected version, candidate directory and installation directory"
version="$1"
candidate_directory="$2"
install_directory="$3"
. "$(dirname "$0")/release-version.sh"
acs_is_release_version "$version" || fail "version must be canonical"
[ "$(uname -s)" = Linux ] || fail "native Linux host required"
case "$(uname -m)" in x86_64 | amd64) ;; *) fail "native amd64 host required" ;; esac
case "$install_directory" in /*) ;; *) fail "absolute installation directory required" ;; esac
candidate_directory="$(cd "$candidate_directory" && pwd -P)" || fail "candidate directory unavailable"
script_directory="$(CDPATH= cd "$(dirname "$0")" && pwd -P)"
cd "$(dirname "$script_directory")"
go run ./tools/releaseverify --dist "$candidate_directory" --version "$version" --linux-candidate

workspace="$(mktemp -d "${TMPDIR:-/tmp}/acs-linux-candidate.XXXXXX")"
trap 'rm -rf "$workspace"' EXIT HUP INT TERM
mkdir "$workspace/home" "$workspace/default-home" "$workspace/expected"
archive="acs_${version#v}_linux_amd64.tar.gz"
tar -xzf "$candidate_directory/$archive" -C "$workspace/expected"
HOME="$workspace/home" sh "$candidate_directory/install.sh" --candidate-dir "$candidate_directory" --bin-dir "$install_directory"
cmp -s "$workspace/expected/acs" "$install_directory/acs" || fail "installer changed candidate bytes"
HOME="$workspace/default-home" sh "$candidate_directory/install.sh" --candidate-dir "$candidate_directory" >"$workspace/default-output"
cmp -s "$workspace/expected/acs" "$workspace/default-home/.local/bin/acs" || fail "default installer changed candidate bytes"

go run ./tools/linuxcandidate --dist "$candidate_directory" --version "$version" --current "$version" --executable "$install_directory/acs"
cmp -s "$workspace/expected/acs" "$install_directory/acs" || fail "updater changed candidate bytes"
[ "$("$install_directory/acs" version)" = "acs $version" ] || fail "unexpected installed version"

reject_launch() {
  if HOME="$workspace/home" "$install_directory/acs" "$@" >"$workspace/rejected" 2>&1; then
    fail "production Linux launch was admitted"
  fi
  grep -F 'Linux sandbox backend is not available yet' "$workspace/rejected" >/dev/null || fail "missing disabled admission diagnostic"
  grep -F 'ACS never runs targets unsandboxed' "$workspace/rejected" >/dev/null || fail "missing containment diagnostic"
}
reject_launch run --profile missing -- /usr/bin/touch "$workspace/unexpected"
reject_launch sandbox --profile missing
reject_launch devin --profile missing
reject_launch codex --profile missing
reject_launch codex auth login --name candidate
reject_launch codex auth status --name candidate
[ ! -e "$workspace/unexpected" ] && [ ! -e "$workspace/home/.acs" ] || fail "disabled launch produced state"
if HOME="$workspace/home" "$install_directory/acs" update --check >"$workspace/update" 2>&1; then
  fail "production Linux updater was admitted"
fi
grep -F 'updates require macOS 26 on Apple Silicon' "$workspace/update" >/dev/null || fail "unexpected production update rejection"
printf '%s\n' 'Linux candidate packaging passed: exact install/update bytes and closed production admission; sandbox qualification is separate.'

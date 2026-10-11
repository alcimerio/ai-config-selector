#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: scripts/fetch-codex-test-targets.sh <lock-file> <output-directory>" >&2
  exit 2
fi

lock_file="$1"
output_directory="$2"

fail() {
  printf 'fetch Codex test targets: %s\n' "$1" >&2
  exit 1
}

[ -f "$lock_file" ] && [ ! -L "$lock_file" ] || fail "lock file is unavailable or unsafe"
if [ -e "$output_directory" ] || [ -L "$output_directory" ]; then
  fail "output directory already exists"
fi

. "$(dirname "$0")/codex-target-lock.sh"
validate_codex_lock
[ "$old_cli:$old_host:$new_cli:$new_host" = "1:1:1:1" ] || fail "lock must contain both reviewed target pairs"

workspace="$(mktemp -d "${output_directory}.fetch.XXXXXX")" || fail "temporary directory could not be created"
chmod 0700 "$workspace" || fail "temporary directory could not be made private"
cleanup() {
  if [ -n "$workspace" ] && [ -d "$workspace" ]; then
    find "$workspace" -type f -exec rm -f {} \;
    rmdir "$workspace" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

while IFS= read -r physical_row || [ -n "$physical_row" ]; do
  IFS='|' read -r version target_os target_arch digest url <<EOF
$physical_row
EOF
  case "$version" in '#'* ) continue ;; esac
  case "$url" in
    */codex-code-mode-host-*) archive="codex_code_mode_host_${version}_${target_os}_${target_arch}.tar.gz" ;;
    *) archive="codex_${version}_${target_os}_${target_arch}.tar.gz" ;;
  esac
  temporary="$workspace/$archive"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output "$temporary" "$url" || fail "approved release asset download failed"
  actual="$(shasum -a 256 "$temporary" | awk '{print $1}')"
  [ "$actual" = "$digest" ] || fail "approved release asset digest did not match the lock"
done <"$lock_file"

mv "$workspace" "$output_directory" || fail "verified release assets could not be published"
workspace=

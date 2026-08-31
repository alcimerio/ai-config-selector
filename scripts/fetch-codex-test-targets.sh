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
mkdir -m 0700 "$output_directory" || fail "output directory could not be created"
workspace="$(mktemp -d "$output_directory/.fetch.XXXXXX")" || fail "temporary directory could not be created"
cleanup() {
  find "$workspace" -type f -exec rm -f {} \;
  rmdir "$workspace" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

count=0
while IFS='|' read -r version target_os target_arch digest url extra; do
  case "$version" in
    ''|'#'*) continue ;;
  esac
  [ -z "$extra" ] || fail "lock entry has unexpected fields"
  [ "$version" = "0.149.1" ] && [ "$target_os" = "darwin" ] || fail "lock entry has an unsupported target"
  case "$target_arch:$url" in
    arm64:https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz) ;;
    amd64:https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz) ;;
    *) fail "lock entry does not name an approved release asset" ;;
  esac
  case "$digest" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) fail "lock entry has an invalid SHA-256 digest" ;;
  esac
  archive="codex_${version}_${target_os}_${target_arch}.tar.gz"
  temporary="$workspace/$archive"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output "$temporary" "$url" || fail "approved release asset download failed"
  actual="$(shasum -a 256 "$temporary" | awk '{print $1}')"
  [ "$actual" = "$digest" ] || fail "approved release asset digest did not match the lock"
  mv "$temporary" "$output_directory/$archive" || fail "verified release asset could not be placed"
  count=$((count + 1))
done <"$lock_file"

[ "$count" -eq 2 ] || fail "lock must contain exactly two supported targets"

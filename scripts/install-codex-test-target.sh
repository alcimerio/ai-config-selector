#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 4 ]; then
  printf '%s\n' "usage: scripts/install-codex-test-target.sh <lock-file> <bundle-directory> <arm64|amd64> <output-path>" >&2
  exit 2
fi

lock_file="$1"
bundle_directory="$2"
target_arch="$3"
output_path="$4"

fail() {
  printf 'install Codex test target: %s\n' "$1" >&2
  exit 1
}

[ -f "$lock_file" ] && [ ! -L "$lock_file" ] || fail "lock file is unavailable or unsafe"
[ -d "$bundle_directory" ] && [ ! -L "$bundle_directory" ] || fail "bundle directory is unavailable or unsafe"
[ ! -e "$output_path" ] && [ ! -L "$output_path" ] || fail "output path already exists"
case "$(uname -s):$(uname -m):$target_arch" in
  Darwin:arm64:arm64|Darwin:aarch64:arm64) member="codex-aarch64-apple-darwin" ;;
  Darwin:x86_64:amd64|Darwin:amd64:amd64) member="codex-x86_64-apple-darwin" ;;
  *) fail "native host does not match the requested target" ;;
esac

version=""
digest=""
count=0
while IFS='|' read -r locked_version target_os locked_arch locked_digest url extra; do
  case "$locked_version" in
    ''|'#'*) continue ;;
  esac
  if [ "$target_os" = "darwin" ] && [ "$locked_arch" = "$target_arch" ]; then
    version="$locked_version"
    digest="$locked_digest"
    count=$((count + 1))
  fi
done <"$lock_file"
[ "$count" -eq 1 ] && [ "$version" = "0.149.1" ] || fail "lock does not contain exactly one requested target"

archive="$bundle_directory/codex_${version}_darwin_${target_arch}.tar.gz"
[ -f "$archive" ] && [ ! -L "$archive" ] || fail "locked release archive is unavailable or unsafe"
actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
[ "$actual" = "$digest" ] || fail "release archive digest did not match the lock"
entries="$(tar -tzf "$archive")" || fail "release archive could not be listed"
[ "$entries" = "$member" ] || fail "release archive contains an unexpected path"
details="$(tar -tvzf "$archive")" || fail "release archive metadata could not be listed"
[ "$(printf '%s' "$details" | cut -c 1)" = "-" ] || fail "release archive member is not a regular file"

output_directory="$(dirname "$output_path")"
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || fail "output directory is unavailable or unsafe"
workspace="$(mktemp -d "$output_directory/.codex-target.XXXXXX")" || fail "temporary install directory could not be created"
cleanup() {
  find "$workspace" -type f -exec rm -f {} \;
  rmdir "$workspace" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
tar -xzf "$archive" -C "$workspace" "$member" || fail "release archive extraction failed"
[ -f "$workspace/$member" ] && [ ! -L "$workspace/$member" ] || fail "extracted target is not a regular file"
chmod 0500 "$workspace/$member" || fail "extracted target could not be secured"
mv "$workspace/$member" "$output_path" || fail "verified target could not be installed"
[ "$("$output_path" --version 2>/dev/null)" = "codex-cli 0.149.1" ] || fail "installed target reported an unexpected version"

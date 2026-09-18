#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 3 ]; then
  printf '%s\n' "usage: scripts/install-devin-test-target.sh <lock-file> <output-directory> <output-binary>" >&2
  exit 2
fi
lock_file="$1"
output_directory="$2"
output_binary="$3"
fail() { printf 'install Devin test target: %s\n' "$1" >&2; exit 1; }
[ -f "$lock_file" ] && [ ! -L "$lock_file" ] || fail "lock file is unavailable or unsafe"
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || fail "output directory is unavailable or unsafe"
[ ! -e "$output_binary" ] && [ ! -L "$output_binary" ] || fail "output path already exists"
case "$(uname -s):$(uname -m)" in Darwin:arm64|Darwin:aarch64) ;; *) fail "native host must be Apple Silicon macOS" ;; esac

version=""; digest=""; url=""; count=0
while IFS='|' read -r locked_version target_os target_arch locked_digest locked_url extra; do
  case "$locked_version" in ''|'#'*) continue ;; esac
  if [ "$target_os" = darwin ] && [ "$target_arch" = arm64 ]; then version="$locked_version"; digest="$locked_digest"; url="$locked_url"; count=$((count+1)); fi
done <"$lock_file"
[ "$count" -eq 1 ] && [ "$version" = 3000.10.21 ] || fail "lock must contain exactly one supported Apple Silicon target"
archive="$output_directory/devin-${version}-darwin-arm64.tar.gz"
[ ! -e "$archive" ] && [ ! -L "$archive" ] || fail "archive destination already exists"
workspace=""
retain_archive=0
cleanup() {
  if [ -n "$workspace" ]; then rm -rf "$workspace"; fi
  if [ "$retain_archive" -ne 1 ]; then rm -f "$archive"; fi
}
trap cleanup EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" "$url" || fail "locked archive download failed"
[ -f "$archive" ] && [ ! -L "$archive" ] || fail "downloaded archive is unsafe"
actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
[ "$actual" = "$digest" ] || fail "archive digest did not match the lock"
entries="$(tar -tzf "$archive")" || fail "archive could not be listed"
printf '%s\n' "$entries" | while IFS= read -r entry; do
  case "$entry" in /*|../*|*/../*|*/..|..|*'\'*) exit 1 ;; esac
done || fail "archive contains an unsafe path"
printf '%s\n' "$entries" | grep -qx 'bin/devin' || fail "archive does not contain bin/devin"
details="$(tar -tvzf "$archive" bin/devin)" || fail "target metadata could not be inspected"
[ "$(printf '%s' "$details" | cut -c 1)" = '-' ] || fail "target member is not a regular file"
workspace="$(mktemp -d "$output_directory/.devin-target.XXXXXX")" || fail "temporary extraction directory could not be created"
tar -xzf "$archive" -C "$workspace" bin/devin || fail "target extraction failed"
[ -f "$workspace/bin/devin" ] && [ ! -L "$workspace/bin/devin" ] || fail "extracted target is unsafe"
chmod 0500 "$workspace/bin/devin" || fail "target permissions could not be secured"
mv "$workspace/bin/devin" "$output_binary" || fail "verified target could not be installed"
version_output="$("$output_binary" --version 2>/dev/null)" || fail "installed target version check failed"
case "$version_output" in *"$version"*) ;; *) fail "installed target reported an unexpected version" ;; esac
retain_archive=1

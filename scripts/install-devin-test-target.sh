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
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) native_os=darwin; native_arch=arm64 ;;
  Linux:x86_64) native_os=linux; native_arch=amd64 ;;
  Linux:arm64|Linux:aarch64) fail "Linux arm64 target qualification is deferred" ;;
  *) fail "native host must be Apple Silicon macOS or Linux amd64" ;;
esac

version=""; digest=""; url=""; count=0
while IFS='|' read -r locked_version target_os target_arch locked_digest locked_url extra; do
  case "$locked_version" in ''|'#'*) continue ;; esac
  if [ "$target_os" = "$native_os" ] && [ "$target_arch" = "$native_arch" ]; then
    [ -z "$extra" ] || fail "malformed target lock row"
    version="$locked_version"; digest="$locked_digest"; url="$locked_url"; count=$((count+1))
  fi
done <"$lock_file"
[ "$count" -eq 1 ] && [ "$version" = 3000.10.21 ] || fail "lock must contain exactly one supported native target"
[ "${#digest}" -eq 64 ] || fail "invalid archive digest"
case "$digest" in *[!0-9a-f]*) fail "invalid archive digest" ;; esac
case "$url" in https://*) ;; *) fail "archive URL must use HTTPS" ;; esac
file_size=""; file_digest=""
if [ "$native_os" = linux ]; then
  file_lock="$(dirname "$lock_file")/devin-test-target-files.lock"
  [ -f "$file_lock" ] && [ ! -L "$file_lock" ] || fail "file lock is unavailable or unsafe"
  count=0
  while IFS='|' read -r locked_version target_os target_arch member size sha extra; do
    case "$locked_version" in ''|'#'*) continue ;; esac
    if [ "$locked_version:$target_os:$target_arch" = "$version:$native_os:$native_arch" ]; then
      [ "$member" = bin/devin ] && [ -z "$extra" ] || fail "unexpected runtime bundle member"
      file_size="$size"; file_digest="$sha"; count=$((count+1))
    fi
  done <"$file_lock"
  [ "$count" -eq 1 ] || fail "file lock must contain exactly the Linux executable"
  case "$file_size" in ''|*[!0-9]*) fail "invalid executable size" ;; esac
  [ "${#file_digest}" -eq 64 ] || fail "invalid executable digest"
  case "$file_digest" in *[!0-9a-f]*) fail "invalid executable digest" ;; esac
fi
archive="$output_directory/devin-${version}-${native_os}-${native_arch}.tar.gz"
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
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
actual="$(sha256 "$archive")"
[ "$actual" = "$digest" ] || fail "archive digest did not match the lock"
entries="$(tar -tzf "$archive")" || fail "archive could not be listed"
printf '%s\n' "$entries" | while IFS= read -r entry; do
  case "$entry" in /*|../*|*/../*|*/..|..|*'\'*) exit 1 ;; esac
done || fail "archive contains an unsafe path"
[ "$(printf '%s\n' "$entries" | grep -cx 'bin/devin')" -eq 1 ] || fail "archive must contain exactly one bin/devin"
details="$(tar -tvzf "$archive" bin/devin)" || fail "target metadata could not be inspected"
[ "$(printf '%s' "$details" | cut -c 1)" = '-' ] || fail "target member is not a regular file"
workspace="$(mktemp -d "$output_directory/.devin-target.XXXXXX")" || fail "temporary extraction directory could not be created"
tar -xzf "$archive" -C "$workspace" bin/devin || fail "target extraction failed"
[ -f "$workspace/bin/devin" ] && [ ! -L "$workspace/bin/devin" ] || fail "extracted target is unsafe"
if [ "$native_os" = linux ]; then
  [ "$(wc -c <"$workspace/bin/devin" | tr -d ' ')" = "$file_size" ] || fail "executable size did not match the file lock"
  [ "$(sha256 "$workspace/bin/devin")" = "$file_digest" ] || fail "executable digest did not match the file lock"
fi
chmod 0500 "$workspace/bin/devin" || fail "target permissions could not be secured"
mv "$workspace/bin/devin" "$output_binary" || fail "verified target could not be installed"
if [ "$native_os" = darwin ]; then
  version_output="$("$output_binary" --version 2>/dev/null)" || fail "installed target version check failed"
  case "$version_output" in *"$version"*) ;; *) fail "installed target reported an unexpected version" ;; esac
fi
# Linux version/preflight execution belongs to the contained native test harness.
retain_archive=1

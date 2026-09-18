#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 4 ]; then
  printf '%s\n' "usage: scripts/install-codex-test-target.sh <lock-file> <bundle-directory> <arm64> <output-path>" >&2
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
  *) fail "native host does not match the requested target" ;;
esac

count=0
arm64_count=0
host_count=0
while IFS= read -r physical_row || [ -n "$physical_row" ]; do
  [ -n "$physical_row" ] || fail "lock contains a blank row"
  IFS='|' read -r version target_os target_arch digest url extra <<EOF
$physical_row
EOF
  case "$version" in
    '#'* ) continue ;;
  esac
  delimiters="$(printf '%s' "$physical_row" | tr -cd '|')"
  [ "${#delimiters}" -eq 4 ] || fail "lock entry has an unexpected field count"
  [ -n "$version" ] && [ -n "$target_os" ] && [ -n "$target_arch" ] && [ -n "$digest" ] && [ -n "$url" ] || fail "lock entry is incomplete"
  [ -z "$extra" ] || fail "lock entry has unexpected fields"
  [ "$version" = "0.149.1" ] && [ "$target_os" = "darwin" ] || fail "lock entry has an unsupported target"
  case "$target_arch:$url" in
    arm64:https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz) role=cli ;;
    arm64:https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-code-mode-host-aarch64-apple-darwin.tar.gz) role=host ;;
    *) fail "lock entry does not name an approved release asset" ;;
  esac
  [ "${#digest}" -eq 64 ] || fail "lock entry has an invalid SHA-256 digest"
  case "$digest" in
    *[!0-9a-f]*) fail "lock entry has an invalid SHA-256 digest" ;;
  esac
  case "$role" in
    cli)
      arm64_count=$((arm64_count + 1))
      arm64_digest="$digest"
      arm64_url="$url"
      ;;
    host)
      host_count=$((host_count + 1))
      host_digest="$digest"
      host_url="$url"
      ;;
  esac
  count=$((count + 1))
done <"$lock_file"

[ "$count" -eq 2 ] && [ "$arm64_count" -eq 1 ] && [ "$host_count" -eq 1 ] || fail "lock must contain exactly one CLI and one code-mode host"


output_directory="$(dirname "$output_path")"
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || fail "output directory is unavailable or unsafe"
host_output="$output_directory/codex-code-mode-host"
[ "$output_path" != "$host_output" ] || fail "CLI output uses the reserved companion name"
[ ! -e "$host_output" ] && [ ! -L "$host_output" ] || fail "code-mode host output already exists"
workspace="$(mktemp -d "$output_directory/.codex-target.XXXXXX")" || fail "temporary install directory could not be created"
publish_started=0
publish_complete=0
cleanup() {
  if [ "$publish_started" -eq 1 ] && [ "$publish_complete" -eq 0 ]; then
    rm -f "$host_output" "$output_path"
  fi
  find "$workspace" -type f -exec rm -f {} \;
  rmdir "$workspace" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# Validate and stage BOTH archives before publishing either executable.
for role in cli host; do
  case "$role" in
    cli) digest="$arm64_digest"; archive="$bundle_directory/codex_0.149.1_darwin_arm64.tar.gz"; member="codex-aarch64-apple-darwin" ;;
    host) digest="$host_digest"; archive="$bundle_directory/codex_code_mode_host_0.149.1_darwin_arm64.tar.gz"; member="codex-code-mode-host-aarch64-apple-darwin" ;;
  esac
  [ -f "$archive" ] && [ ! -L "$archive" ] || fail "locked release archive is unavailable or unsafe"
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  [ "$actual" = "$digest" ] || fail "release archive digest did not match the lock"
  entries="$(tar -tzf "$archive")" || fail "release archive could not be listed"
  [ "$entries" = "$member" ] || fail "release archive contains an unexpected path"
  details="$(tar -tvzf "$archive")" || fail "release archive metadata could not be listed"
  [ "$(printf '%s' "$details" | cut -c 1)" = "-" ] || fail "release archive member is not a regular file"
  tar -xzf "$archive" -C "$workspace" "$member" || fail "release archive extraction failed"
  [ -f "$workspace/$member" ] && [ ! -L "$workspace/$member" ] || fail "extracted target is not a regular file"
  chmod 0500 "$workspace/$member" || fail "extracted target could not be secured"
done
[ "$("$workspace/codex-aarch64-apple-darwin" --version 2>/dev/null)" = "codex-cli 0.149.1" ] || fail "installed target reported an unexpected version"
publish_started=1
mv "$workspace/codex-code-mode-host-aarch64-apple-darwin" "$host_output" || fail "verified host could not be installed"
if ! mv "$workspace/codex-aarch64-apple-darwin" "$output_path"; then
  rm -f "$host_output"
  fail "verified target could not be installed"
fi
publish_complete=1

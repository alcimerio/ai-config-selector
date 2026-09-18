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

workspace="$(mktemp -d "${output_directory}.fetch.XXXXXX")" || fail "temporary directory could not be created"
chmod 0700 "$workspace" || fail "temporary directory could not be made private"
cleanup() {
  if [ -n "$workspace" ] && [ -d "$workspace" ]; then
    find "$workspace" -type f -exec rm -f {} \;
    rmdir "$workspace" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

for role in cli host; do
  case "$role" in
    cli) digest="$arm64_digest"; url="$arm64_url"; archive="codex_0.149.1_darwin_arm64.tar.gz" ;;
    host) digest="$host_digest"; url="$host_url"; archive="codex_code_mode_host_0.149.1_darwin_arm64.tar.gz" ;;
  esac
  temporary="$workspace/$archive"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output "$temporary" "$url" || fail "approved release asset download failed"
  actual="$(shasum -a 256 "$temporary" | awk '{print $1}')"
  [ "$actual" = "$digest" ] || fail "approved release asset digest did not match the lock"
done

mv "$workspace" "$output_directory" || fail "verified release assets could not be published"
workspace=

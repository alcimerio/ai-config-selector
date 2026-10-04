#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 4 ] && [ "$#" -ne 5 ]; then
  printf '%s\n' "usage: scripts/install-codex-test-target.sh <lock-file> <bundle-directory> <arm64> <output-path> [reviewed-version]" >&2
  exit 2
fi

lock_file="$1"
bundle_directory="$2"
target_arch="$3"
output_path="$4"
selected_version="${5-0.149.1}"

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

case "$selected_version" in 0.149.1|0.156.0) ;; *) fail "requested version is not reviewed" ;; esac
. "$(dirname "$0")/codex-target-lock.sh"
validate_codex_lock
[ -n "${arm64_digest:-}" ] && [ -n "${host_digest:-}" ] || fail "requested version is absent from the lock"

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
    cli) digest="$arm64_digest"; archive="$bundle_directory/codex_${selected_version}_darwin_arm64.tar.gz"; member="codex-aarch64-apple-darwin" ;;
    host) digest="$host_digest"; archive="$bundle_directory/codex_code_mode_host_${selected_version}_darwin_arm64.tar.gz"; member="codex-code-mode-host-aarch64-apple-darwin" ;;
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
[ "$("$workspace/codex-aarch64-apple-darwin" --version 2>/dev/null)" = "codex-cli $selected_version" ] || fail "installed target reported an unexpected version"
publish_started=1
mv "$workspace/codex-code-mode-host-aarch64-apple-darwin" "$host_output" || fail "verified host could not be installed"
if ! mv "$workspace/codex-aarch64-apple-darwin" "$output_path"; then
  rm -f "$host_output"
  fail "verified target could not be installed"
fi
publish_complete=1

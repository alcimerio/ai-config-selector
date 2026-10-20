#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 4 ]; then
  printf '%s\n' "usage: scripts/install-grok-test-target.sh <lock-file> <archive> <arm64|amd64> <output-path>" >&2
  exit 2
fi

lock_file="$1"
archive="$2"
target_arch="$3"
output_path="$4"

fail() {
  printf 'install Grok test target: %s\n' "$1" >&2
  exit 1
}

[ -f "$lock_file" ] && [ ! -L "$lock_file" ] || fail "lock file is unavailable or unsafe"
[ -f "$archive" ] && [ ! -L "$archive" ] || fail "archive is unavailable or unsafe"
[ ! -e "$output_path" ] && [ ! -L "$output_path" ] || fail "output path already exists"
case "$target_arch" in arm64|amd64) ;; *) fail "requested architecture is not reviewed" ;; esac

case "$(uname -s):$(uname -m):$target_arch" in
  Darwin:arm64:arm64|Darwin:aarch64:arm64) host_key="darwin|arm64" ;;
  Linux:x86_64:amd64) host_key="linux|amd64" ;;
  Linux:aarch64:arm64|Linux:arm64:arm64) host_key="linux|arm64" ;;
  *) fail "native host does not match the requested target" ;;
esac

digest=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ""|\#*) continue ;;
  esac
  case "$line" in
    "1.0.62|$host_key|"*)
      rest="${line#1.0.62|$host_key|}"
      digest="${rest%%|*}"
      ;;
  esac
done < "$lock_file"
[ -n "$digest" ] || fail "requested version is absent from the lock"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$archive" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
fi
[ "$actual" = "$digest" ] || fail "archive digest did not match the lock"

output_directory="$(dirname "$output_path")"
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || fail "output directory is unavailable or unsafe"
workspace="$(mktemp -d "$output_directory/.grok-target.XXXXXX")" || fail "temporary install directory could not be created"
publish_started=0
publish_complete=0
cleanup() {
  if [ "$publish_started" -eq 1 ] && [ "$publish_complete" -eq 0 ]; then
    rm -f "$output_path"
  fi
  rm -rf "$workspace"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

zstd -d -q -f -o "$workspace/grok" "$archive" || fail "archive extraction failed"
[ -f "$workspace/grok" ] && [ ! -L "$workspace/grok" ] || fail "extracted target is not a regular file"
chmod 0500 "$workspace/grok" || fail "extracted target could not be secured"
# Linux execution belongs to the contained native harness. Darwin still checks
# the reported version here because that host has no contained Grok gate.
case "$(uname -s)" in
  Linux) ;;
  *)
    version="$("$workspace/grok" --version 2>/dev/null || true)"
    printf '%s\n' "$version" | grep -Eq '^grok 1\.0\.62( \([0-9a-f]+\))?$' || fail "installed target reported an unexpected version"
    ;;
esac
publish_started=1
mv "$workspace/grok" "$output_path" || fail "extracted target could not be published"
publish_complete=1

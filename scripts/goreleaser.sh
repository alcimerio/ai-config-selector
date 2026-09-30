#!/bin/sh

set -eu

readonly goreleaser_version="2.18.2"
readonly base_url="https://github.com/goreleaser/goreleaser/releases/download/v${goreleaser_version}"

case "$(uname -s)" in
  Darwin) tool_os="Darwin" ;;
  Linux) tool_os="Linux" ;;
  *)
    printf '%s\n' "goreleaser: unsupported validation host operating system" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64 | aarch64) tool_arch="arm64" ;;
  x86_64 | amd64) tool_arch="x86_64" ;;
  *)
    printf '%s\n' "goreleaser: unsupported validation host architecture" >&2
    exit 1
    ;;
esac

asset="goreleaser_${tool_os}_${tool_arch}.tar.gz"
case "${tool_os}/${tool_arch}" in
  Darwin/arm64) expected_checksum="a811ff154fe136a0cfb55d00126c151fc39ec370a663d805a9ca5547445aa70c" ;;
  Linux/arm64) expected_checksum="a71681b29194f08f057a68cfcaa5c6b15d907a83a2622c51900c4faff828f322" ;;
  Linux/x86_64) expected_checksum="0a96edc9d9bc594e4a41cc4d59467c182062910ab24d9d1f6dd7b667d32606d3" ;;
  *)
    printf '%s\n' "goreleaser: unsupported validation host" >&2
    exit 1
    ;;
esac

for prerequisite in awk curl tar; do
  if ! command -v "$prerequisite" >/dev/null 2>&1; then
    printf 'goreleaser: required tool is unavailable: %s\n' "$prerequisite" >&2
    exit 1
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  checksum_command="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  checksum_command="shasum -a 256"
else
  printf '%s\n' "goreleaser: sha256sum or shasum is required" >&2
  exit 1
fi

workspace="$(mktemp -d "${TMPDIR:-/tmp}/acs-goreleaser.XXXXXX")"
cleanup() {
  rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$workspace/$asset" "$base_url/$asset"
actual_checksum="$($checksum_command "$workspace/$asset" | awk '{print $1}')"
if [ "$actual_checksum" != "$expected_checksum" ]; then
  printf '%s\n' "goreleaser: downloaded tool checksum mismatch" >&2
  exit 1
fi
tar -xzf "$workspace/$asset" -C "$workspace" goreleaser
"$workspace/goreleaser" "$@"

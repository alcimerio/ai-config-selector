#!/bin/sh

set -eu

readonly goreleaser_version="2.17.1"
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
  Darwin/arm64) expected_checksum="b65624885c25da9a677b7ad11cf86a02123cc5a56af66f6b4ebb574658eada2e" ;;
  Darwin/x86_64) expected_checksum="a92a68c61a6833ff67748f532cbebc7b8e49ba30de062ab463b221211ee6368f" ;;
  Linux/arm64) expected_checksum="702f03769ac8bcb0e47839c82243cc614ae995633599a98c63062e13ea85f829" ;;
  Linux/x86_64) expected_checksum="a99bbc7ae0d8d897b07c4c497a9b62f222558804715ef219d1af05a7e417bc80" ;;
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

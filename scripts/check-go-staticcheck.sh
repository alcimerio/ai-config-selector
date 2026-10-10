#!/bin/sh

set -eu

usage() {
  printf '%s\n' 'usage: scripts/check-go-staticcheck.sh <darwin arm64 | linux amd64>' >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
case "$1/$2" in
  darwin/arm64|linux/amd64) ;;
  *) usage ;;
esac
target_os="$1"
target_arch="$2"

script_directory="$(CDPATH='' cd "$(dirname "$0")" && pwd -P)"
cd "$(dirname "$script_directory")"

# Build the checker for the host; select the analysis target only at execution.
unset GOOS GOARCH CGO_ENABLED GOVERSION
GOWORK=off
export GOWORK

# Version-suffixed go run ignores this repository's go.mod. Resolve the project
# toolchain first so the checker can read the same Go version's export data.
GOTOOLCHAIN="$(go env GOVERSION)"
export GOTOOLCHAIN

# This revision pins x/tools v0.51.0 to read Go 1.27 export data.
exec go run -exec "env GOOS=$target_os GOARCH=$target_arch CGO_ENABLED=0" \
  honnef.co/go/tools/cmd/staticcheck@v0.7.0-0.dev.0.20261009230814-452d5bb86b45 \
  -tests=true ./...

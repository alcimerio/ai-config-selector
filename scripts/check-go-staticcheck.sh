#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
  printf '%s\n' 'usage: scripts/check-go-staticcheck.sh linux amd64 | darwin arm64' >&2
  exit 2
fi
case "$1/$2" in
  linux/amd64|darwin/arm64) ;;
  *) printf '%s\n' 'unsupported Staticcheck target' >&2; exit 2 ;;
esac

script_directory="$(CDPATH='' cd "$(dirname "$0")" && pwd -P)"
cd "$(dirname "$script_directory")"

# A versioned go run ignores this module when selecting its own toolchain.
# Select the module's exact Go version before building the analyzer, instead
# of accepting its older minimum or an already installed Staticcheck binary.
GOTOOLCHAIN="$(awk '$1 == "go" { print "go" $2; exit }' go.mod)"
[ -n "$GOTOOLCHAIN" ] || { printf '%s\n' 'go.mod must specify a Go version' >&2; exit 1; }
export GOTOOLCHAIN

# Build for the host even when the caller has cross-compilation settings.
# Apply the analysis target only when running Staticcheck, including tests.
unset GOOS GOARCH CGO_ENABLED
# This revision pins x/tools v0.51.0 to read Go 1.27 export data.
exec go run -exec "env GOOS=$1 GOARCH=$2 CGO_ENABLED=0" \
  honnef.co/go/tools/cmd/staticcheck@v0.7.0-0.dev.0.20261009230814-452d5bb86b45 -tests ./...

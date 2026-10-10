#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' "usage: scripts/release-candidate.sh <vMAJOR.MINOR.PATCH>" >&2
  exit 2
fi

release_tag="$1"
archive_version="${release_tag#v}"
. "$(dirname "$0")/release-version.sh"

canonical_version_error() {
	printf '%s\n' "release candidate version must be a canonical SemVer tag" >&2
	exit 2
}

acs_is_release_version "$release_tag" || canonical_version_error

if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
	printf '%s\n' "release candidate source must be a clean Git worktree" >&2
	exit 1
fi

scripts/goreleaser.sh check
ACS_RELEASE_VERSION="$archive_version" scripts/goreleaser.sh release --snapshot --clean

# These disjoint sets share one build. Only release-candidate is publishable.
for target in darwin_arm64 linux_amd64; do
  candidate_directory="dist/release-candidate"
  if [ "$target" = linux_amd64 ]; then
    candidate_directory="dist/linux-candidate"
  fi
  mkdir "$candidate_directory"
  artifact="acs_${archive_version}_${target}.tar.gz"
  cp "dist/$artifact" "$candidate_directory/$artifact"
  # Preserve GoReleaser's digest for these exact bytes, without cross-set rows.
  awk -v artifact="$artifact" '$2 == artifact { print; count++ } END { if (count != 1) exit 1 }' \
    dist/SHA256SUMS >"$candidate_directory/SHA256SUMS"
  go run ./tools/renderinstaller \
    --template scripts/install.sh.tmpl \
    --output "$candidate_directory/install.sh" \
    --version "$release_tag"
  sh -n "$candidate_directory/install.sh"
  if [ "$target" = linux_amd64 ]; then
    go run ./tools/releaseverify --dist "$candidate_directory" --version "$release_tag" --linux-candidate
  else
    go run ./tools/releaseverify --dist "$candidate_directory" --version "$release_tag"
  fi
done

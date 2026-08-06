#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' "usage: scripts/release-candidate.sh <vMAJOR.MINOR.PATCH>" >&2
  exit 2
fi

release_tag="$1"
archive_version="${release_tag#v}"

canonical_version_error() {
	printf '%s\n' "release candidate version must be a canonical SemVer tag" >&2
	exit 2
}

if [ "$release_tag" = "$archive_version" ]; then
	canonical_version_error
fi
case "$archive_version" in
	*[!0-9.]*) canonical_version_error ;;
esac

old_ifs="$IFS"
IFS=.
set -- $archive_version
IFS="$old_ifs"
if [ "$#" -ne 3 ]; then
	canonical_version_error
fi
for component in "$@"; do
	case "$component" in
		0 | [1-9] | [1-9][0-9]*) ;;
		*) canonical_version_error ;;
	esac
done

if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
	printf '%s\n' "release candidate source must be a clean Git worktree" >&2
	exit 1
fi

scripts/goreleaser.sh check
ACS_RELEASE_VERSION="$archive_version" scripts/goreleaser.sh release --snapshot --clean

candidate_directory="dist/release-candidate"
mkdir "$candidate_directory"
for artifact in \
  "acs_${archive_version}_darwin_arm64.tar.gz" \
  "acs_${archive_version}_darwin_amd64.tar.gz" \
  "acs_${archive_version}_linux_amd64.tar.gz" \
  "acs_${archive_version}_linux_arm64.tar.gz" \
  SHA256SUMS
do
  cp "dist/$artifact" "$candidate_directory/$artifact"
done

go run ./tools/renderinstaller \
  --template scripts/install.sh.tmpl \
  --output "$candidate_directory/install.sh" \
  --version "$release_tag"
sh -n "$candidate_directory/install.sh"
go run ./tools/releaseverify --dist "$candidate_directory" --version "$release_tag"

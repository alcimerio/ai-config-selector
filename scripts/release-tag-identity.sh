#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
  printf '%s\n' "usage: scripts/release-tag-identity.sh <vMAJOR.MINOR.PATCH>" >&2
  exit 2
fi

release_tag="$1"
archive_version="${release_tag#v}"
tag_identity="unvalidated"

fail() {
  printf 'release tag identity failed: tag=%s stage=%s: %s\n' "$tag_identity" "$stage" "$1" >&2
  exit 1
}

stage="tag-name"
case "$release_tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "tag is not a canonical SemVer release" ;;
esac
case "$archive_version" in
  *[!0-9.]*) fail "tag is not a canonical SemVer release" ;;
esac
old_ifs="$IFS"
IFS=.
set -- $archive_version
IFS="$old_ifs"
[ "$#" -eq 3 ] || fail "tag is not a canonical SemVer release"
for component in "$@"; do
  case "$component" in
    0 | [1-9] | [1-9][0-9]*) ;;
    *) fail "tag is not a canonical SemVer release" ;;
  esac
done
tag_identity="$release_tag"

stage="repository"
[ -z "$(git status --porcelain --untracked-files=all)" ] || fail "source worktree is not clean"
tag_ref="refs/tags/$release_tag"
[ "$(git cat-file -t "$tag_ref" 2>/dev/null || true)" = "tag" ] || fail "release tag is not annotated"
source_commit="$(git rev-parse "$tag_ref^{}" 2>/dev/null)" || fail "tagged source commit is unavailable"
tag_object="$(git rev-parse "$tag_ref" 2>/dev/null)" || fail "annotated tag object is unavailable"
case "$source_commit" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) fail "tagged source commit is invalid" ;;
esac
[ "$(git rev-parse HEAD)" = "$source_commit" ] || fail "checked-out source does not match the tag"

stage="release-notes"
release_notes="docs/releases/$release_tag.md"
[ -f "$release_notes" ] && [ ! -L "$release_notes" ] && [ -s "$release_notes" ] || fail "version-controlled release notes are missing"

stage="annotation"
annotation="$(git for-each-ref --format='%(contents)' "$tag_ref")" || fail "annotated tag message is unavailable"
[ -n "$annotation" ] || fail "annotated tag message is empty"

printf '%s\n%s\n' "$source_commit" "$tag_object"

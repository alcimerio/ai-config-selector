#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: scripts/release-tag-identity.sh <vMAJOR.MINOR.PATCH> <evidence-output>" >&2
  exit 2
fi

release_tag="$1"
evidence_output="$2"
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

stage="evidence"
umask 077
git for-each-ref --format='%(contents)' "$tag_ref" >"$evidence_output" || fail "annotated evidence could not be extracted"
[ -s "$evidence_output" ] || fail "annotated evidence is missing"

earliest_completion="$(git show -s --format=%cI "$source_commit")" || fail "source timestamp is unavailable"
latest_completion="$(git for-each-ref --format='%(taggerdate:iso-strict)' "$tag_ref")" || fail "tag timestamp is unavailable"
[ -n "$earliest_completion" ] && [ -n "$latest_completion" ] || fail "release review window is unavailable"

printf '%s\n%s\n%s\n%s\n' "$source_commit" "$tag_object" "$earliest_completion" "$latest_completion"

#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: scripts/prepare-release-tag.sh <vMAJOR.MINOR.PATCH> <evidence-set.json>" >&2
  exit 2
fi

release_tag="$1"
evidence_file="$2"
archive_version="${release_tag#v}"
stage="arguments"
tag_identity="unvalidated"
source_identity="unvalidated"
created_tag=false
identity_output=""

fail() {
  printf 'release tag preparation failed: tag=%s source=%s stage=%s: %s\n' \
    "$tag_identity" "$source_identity" "$stage" "$1" >&2
  exit 1
}

cleanup() {
  if [ "$created_tag" = true ]; then
    git tag -d "$release_tag" >/dev/null 2>&1 || true
  fi
  if [ -n "$identity_output" ]; then
    rm -f "$identity_output" "$identity_output.values"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$release_tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "release tag is not canonical SemVer" ;;
esac
case "$archive_version" in
  *[!0-9.]*) fail "release tag is not canonical SemVer" ;;
esac
old_ifs="$IFS"
IFS=.
set -- $archive_version
IFS="$old_ifs"
[ "$#" -eq 3 ] || fail "release tag is not canonical SemVer"
for component in "$@"; do
  case "$component" in
    0 | [1-9] | [1-9][0-9]*) ;;
    *) fail "release tag is not canonical SemVer" ;;
  esac
done
tag_identity="$release_tag"

[ -f "$evidence_file" ] && [ ! -L "$evidence_file" ] && [ -s "$evidence_file" ] || \
  fail "authenticated evidence set is unavailable or unsafe"

stage="repository"
[ -z "$(git status --porcelain --untracked-files=all)" ] || fail "source worktree is not clean"
[ "$(git branch --show-current)" = "main" ] || fail "release source is not checked out on main"
source_commit="$(git rev-parse HEAD 2>/dev/null)" || fail "source commit is unavailable"
source_identity="$source_commit"
remote_main="$(git rev-parse refs/remotes/origin/main 2>/dev/null)" || \
  fail "origin/main is unavailable; fetch it before preparing the tag"
[ "$source_commit" = "$remote_main" ] || fail "source commit does not match fetched origin/main"

tag_ref="refs/tags/$release_tag"
if git show-ref --verify --quiet "$tag_ref"; then
  fail "release tag already exists locally"
fi
if git ls-remote --exit-code --refs origin "$tag_ref" >/dev/null 2>&1; then
  fail "release tag already exists on origin"
else
  remote_status=$?
  [ "$remote_status" -eq 2 ] || fail "remote release tag state could not be verified"
fi

release_notes="docs/releases/$release_tag.md"
[ -f "$release_notes" ] && [ ! -L "$release_notes" ] && [ -s "$release_notes" ] || \
  fail "version-controlled release notes are unavailable or unsafe"

stage="candidate"
scripts/release-candidate.sh "$release_tag" || fail "release candidate validation failed"

stage="evidence"
earliest_completion="$(git show -s --format=%cI "$source_commit")" || \
  fail "source timestamp is unavailable"
latest_completion="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || fail "review timestamp is unavailable"
go run ./tools/releasegate \
  --evidence "$evidence_file" \
  --candidate dist/release-candidate \
  --version "$release_tag" \
  --source-commit "$source_commit" \
  --earliest-completion "$earliest_completion" \
  --latest-completion "$latest_completion" >/dev/null || \
  fail "authenticated evidence does not match the release candidate"

stage="create-tag"
git tag -a "$release_tag" -F "$evidence_file" "$source_commit" || fail "annotated release tag could not be created"
created_tag=true

identity_output="$(mktemp "${TMPDIR:-/tmp}/acs-release-tag.XXXXXX")" || \
  fail "temporary identity output could not be created"
scripts/release-tag-identity.sh "$release_tag" "$identity_output.values" >"$identity_output" || \
  fail "created release tag failed identity validation"

prepared_source="$(sed -n '1p' "$identity_output")"
tag_object="$(sed -n '2p' "$identity_output")"
[ "$(sed -n '3p' "$identity_output")" = "$earliest_completion" ] || \
  fail "created tag review window does not preserve the source boundary"
tag_completion="$(sed -n '4p' "$identity_output")"
[ "$prepared_source" = "$source_commit" ] || fail "created tag source commit does not match"
case "$tag_object" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) fail "created annotated tag object is invalid" ;;
esac
go run ./tools/releasegate \
  --evidence "$identity_output.values" \
  --candidate dist/release-candidate \
  --version "$release_tag" \
  --source-commit "$source_commit" \
  --earliest-completion "$earliest_completion" \
  --latest-completion "$tag_completion" >/dev/null || \
  fail "created tag annotation does not preserve valid authenticated evidence"
rm -f "$identity_output.values"

created_tag=false
stage="complete"
printf 'release tag prepared: tag=%s source=%s object=%s status=local-only\n' \
  "$release_tag" "$source_commit" "$tag_object"
printf 'after explicit approval, push only this tag with: git push origin %s\n' "$tag_ref"

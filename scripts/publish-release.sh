#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

if [[ $# -ne 5 ]]; then
  echo "usage: scripts/publish-release.sh <vMAJOR.MINOR.PATCH> <source-commit> <tag-object> <candidate-directory> <release-notes>" >&2
  exit 2
fi

release_tag="$1"
source_commit="$2"
expected_tag_object="$3"
candidate_directory="$4"
release_notes="$5"
repository="${GITHUB_REPOSITORY:-}"
tag_ruleset_id="${ACS_RELEASE_TAG_RULESET_ID:-}"
tag_creation_ruleset_id="${ACS_RELEASE_TAG_CREATION_RULESET_ID:-}"
tag_creator_id="${ACS_RELEASE_TAG_CREATOR_ID:-}"
event_actor_id="${ACS_RELEASE_ACTOR_ID:-}"
policy_token="${ACS_RELEASE_POLICY_TOKEN:-}"
stage="arguments"
tag_identity="unvalidated"
source_identity="unvalidated"

fail() {
  printf 'release publication failed: tag=%s source=%s stage=%s: %s\n' "$tag_identity" "$source_identity" "$stage" "$1" >&2
  exit 1
}

[[ "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail "release tag is invalid"
tag_identity="$release_tag"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || fail "source commit is invalid"
source_identity="$source_commit"
[[ "$expected_tag_object" =~ ^[0-9a-f]{40}$ ]] || fail "annotated tag object is invalid"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "repository identity is invalid"
[[ "$tag_ruleset_id" =~ ^[1-9][0-9]*$ ]] || fail "release tag ruleset identity is invalid"
[[ "$tag_creation_ruleset_id" =~ ^[1-9][0-9]*$ ]] || fail "release tag creation ruleset identity is invalid"
[[ "$tag_creator_id" =~ ^[1-9][0-9]*$ && "$event_actor_id" == "$tag_creator_id" ]] || fail "release tag creator is not authorized"
[[ -n "${GH_TOKEN:-}" ]] || fail "GitHub token is unavailable"
[[ -n "$policy_token" ]] || fail "release policy token is unavailable"
[[ -d "$candidate_directory" && ! -L "$candidate_directory" ]] || fail "candidate directory is unavailable or unsafe"
[[ -f "$release_notes" && ! -L "$release_notes" && -s "$release_notes" ]] || fail "release notes are unavailable or unsafe"

stage="candidate"
go run ./tools/releaseverify --dist "$candidate_directory" --version "$release_tag" >/dev/null || fail "candidate artifact set is invalid"

workspace="$(mktemp -d "${RUNNER_TEMP:-/tmp}/acs-release.XXXXXX")" || fail "temporary workspace could not be created"
cleanup() { rm -rf "$workspace"; }
trap cleanup EXIT
release_json="$workspace/release.json"
plan_file="$workspace/plan"

stage="immutable-setting"
require_immutable_releases() {
  if ! immutable_setting="$(GH_TOKEN="$policy_token" gh api "repos/$repository/immutable-releases" --jq '.enabled' 2>/dev/null)"; then
    fail "immutable Releases setting could not be verified"
  fi
  [[ "$immutable_setting" == "true" ]] || fail "immutable Releases are not enabled"
}
require_immutable_releases

require_release_policy() {
  local protected creation_protected
  if ! protected="$(GH_TOKEN="$policy_token" gh api "repos/$repository/rulesets/$tag_ruleset_id" --jq '(type == "object") and has("bypass_actors") and (.bypass_actors | type == "array") and ((.bypass_actors | length) == 0) and has("conditions") and (.conditions | type == "object") and (.conditions.ref_name.include | type == "array") and (.conditions.ref_name.exclude | type == "array") and (.conditions.ref_name.include == ["refs/tags/v*"]) and ((.conditions.ref_name.exclude | length) == 0) and has("rules") and (.rules | type == "array") and (.target == "tag") and (.enforcement == "active") and (any(.rules[]; .type == "update")) and (any(.rules[]; .type == "deletion"))' 2>/dev/null)"; then
    fail "release tag protection could not be verified"
  fi
  [[ "$protected" == "true" ]] || fail "release tag update and deletion protection is incomplete"
  if ! creation_protected="$(GH_TOKEN="$policy_token" gh api "repos/$repository/rulesets/$tag_creation_ruleset_id" --jq '(type == "object") and has("bypass_actors") and (.bypass_actors | type == "array") and ((.bypass_actors | length) == 1) and (.bypass_actors[0].actor_type == "User") and (.bypass_actors[0].actor_id == '"$tag_creator_id"') and (.bypass_actors[0].bypass_mode == "always") and has("conditions") and (.conditions | type == "object") and (.conditions.ref_name.include | type == "array") and (.conditions.ref_name.exclude | type == "array") and (.conditions.ref_name.include == ["refs/tags/v*"]) and ((.conditions.ref_name.exclude | length) == 0) and has("rules") and (.rules | type == "array") and (.target == "tag") and (.enforcement == "active") and (any(.rules[]; .type == "creation"))' 2>/dev/null)"; then
    fail "release tag creation authorization could not be verified"
  fi
  [[ "$creation_protected" == "true" ]] || fail "release tag creation authorization is incomplete"
}

require_remote_tag_identity() {
  local ref_identity target_identity comparison ref_type ref_sha target_type target_sha
  if ! ref_identity="$(gh api "repos/$repository/git/ref/tags/$release_tag" --jq '.object.type + "\t" + .object.sha' 2>/dev/null)"; then
    fail "remote release tag could not be read"
  fi
  read -r ref_type ref_sha <<<"$ref_identity"
  [[ "$ref_type" == "tag" && "$ref_sha" == "$expected_tag_object" ]] || fail "remote annotated tag object does not match"
  if ! target_identity="$(gh api "repos/$repository/git/tags/$ref_sha" --jq '.object.type + "\t" + .object.sha' 2>/dev/null)"; then
    fail "remote annotated tag target could not be read"
  fi
  read -r target_type target_sha <<<"$target_identity"
  [[ "$target_type" == "commit" && "$target_sha" == "$source_commit" ]] || fail "remote tag source commit does not match"
  if ! comparison="$(gh api "repos/$repository/compare/$source_commit...main" --jq '.status' 2>/dev/null)"; then
    fail "protected main ancestry could not be verified"
  fi
  [[ "$comparison" == "ahead" || "$comparison" == "identical" ]] || fail "tagged source is not contained in protected main"
}

require_release_policy
require_remote_tag_identity

fetch_release() {
  gh api "repos/$repository/releases/tags/$release_tag" >"$release_json" 2>/dev/null
}

fetch_release_by_id() {
  local release_id="$1"
  [[ "$release_id" =~ ^[1-9][0-9]*$ ]] || return 1
  gh api "repos/$repository/releases/$release_id" >"$release_json" 2>/dev/null
}

stage="discover"
release_exists=true
if ! fetch_release; then
  # The tag endpoint omits draft Releases. A successful list query distinguishes
  # an absent Release from a draft and from an API/authentication failure.
  if ! existing_id="$(gh api --paginate "repos/$repository/releases" --jq ".[] | select(.tag_name == \"$release_tag\") | .id" 2>/dev/null)"; then
    fail "GitHub Release state could not be read"
  fi
  if [[ -z "$existing_id" ]]; then
    release_exists=false
  else
    [[ "$existing_id" =~ ^[1-9][0-9]*$ ]] || fail "GitHub Release lookup returned conflicting state"
    fetch_release_by_id "$existing_id" || fail "GitHub draft Release state could not be read"
  fi
fi

plan() {
  local arguments=(--candidate "$candidate_directory" --version "$release_tag" --source-commit "$source_commit" --release-notes "$release_notes")
  if [[ "$release_exists" == true ]]; then
    arguments+=(--release-json "$release_json")
  fi
  go run ./tools/releasepublish "${arguments[@]}" >"$plan_file" || fail "Release state is not safe to advance"
}

read_plan() {
  state=""
  release_id=""
  publish=""
  uploads=()
  while IFS=$'\t' read -r key value; do
    case "$key" in
      state) state="$value" ;;
      release-id) release_id="$value" ;;
      publish) publish="$value" ;;
      upload) uploads+=("$value") ;;
      *) fail "publication plan is malformed" ;;
    esac
  done <"$plan_file"
  [[ -n "$state" && "$release_id" =~ ^[0-9]+$ && "$publish" =~ ^(true|false)$ ]] || fail "publication plan is incomplete"
}

plan
read_plan
if [[ "$state" == "complete" ]]; then
  printf 'release publication: tag=%s source=%s stage=complete status=unchanged\n' "$release_tag" "$source_commit"
  exit 0
fi

if [[ "$state" == "create-draft" ]]; then
  stage="create-draft"
  require_release_policy
  require_remote_tag_identity
  if ! gh api --method POST "repos/$repository/releases" \
    -f tag_name="$release_tag" -f target_commitish="$source_commit" -f name="ACS $release_tag" \
    -F draft=true -F prerelease=false -F generate_release_notes=false -F body="@$release_notes" \
    >"$release_json" 2>/dev/null; then
    fail "draft Release could not be created"
  fi
  release_exists=true
  plan
  read_plan
fi

if [[ "$state" == "resume-draft" ]]; then
  stage="upload-assets"
  for asset in "${uploads[@]}"; do
    if ! gh release upload "$release_tag" "$candidate_directory/$asset" --repo "$repository" 2>/dev/null; then
      fail "a missing Release asset could not be uploaded"
    fi
  done
  stage="verify-draft"
  fetch_release_by_id "$release_id" || fail "staged Release state could not be read"
  plan
  read_plan
fi

[[ "$state" == "publish-draft" && "$publish" == "true" ]] || fail "draft is not complete enough to publish"
stage="publish"
require_immutable_releases
require_release_policy
require_remote_tag_identity
if ! gh api --method PATCH "repos/$repository/releases/$release_id" -F draft=false >"$release_json" 2>/dev/null; then
  fail "complete draft could not be published"
fi

stage="verify-immutable"
verified=false
for attempt in 1 2 3 4 5; do
  if fetch_release_by_id "$release_id" && go run ./tools/releasepublish --candidate "$candidate_directory" --version "$release_tag" --source-commit "$source_commit" --release-notes "$release_notes" --release-json "$release_json" >"$plan_file" 2>/dev/null; then
    read_plan
    if [[ "$state" == "complete" ]]; then
      verified=true
      break
    fi
  fi
  sleep 2
done
[[ "$verified" == true ]] || fail "published Release did not become immutable with the exact asset set"
printf 'release publication: tag=%s source=%s stage=complete status=published\n' "$release_tag" "$source_commit"

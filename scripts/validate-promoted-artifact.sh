#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 5 ]; then
  printf '%s\n' "usage: scripts/validate-promoted-artifact.sh <vMAJOR.MINOR.PATCH> <darwin|linux> <amd64|arm64> <candidate-directory> <install-directory>" >&2
  exit 2
fi

candidate_version="$1"
target_os="$2"
target_arch="$3"
candidate_directory="$4"
install_directory="$5"
candidate_identity="candidate=unvalidated"
target_identity="unvalidated"
stage="arguments"

fail() {
  printf 'promoted artifact validation failed: target=%s %s stage=%s: %s\n' \
    "$target_identity" "$candidate_identity" "$stage" "$1" >&2
  exit 1
}

passed() {
  printf 'promoted artifact validation: target=%s %s stage=%s status=passed\n' \
    "$target_identity" "$candidate_identity" "$stage"
}

archive_version="${candidate_version#v}"
case "$candidate_version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "candidate version is not a canonical SemVer tag" ;;
esac
old_ifs="$IFS"
IFS=.
set -- $archive_version
IFS="$old_ifs"
if [ "$#" -ne 3 ]; then
  fail "candidate version is not a canonical SemVer tag"
fi
for component in "$@"; do
  case "$component" in
    0 | [1-9] | [1-9][0-9]*) ;;
    *) fail "candidate version is not a canonical SemVer tag" ;;
  esac
done

case "$target_os/$target_arch" in
  darwin/arm64 | darwin/amd64 | linux/amd64 | linux/arm64) ;;
  *) fail "unsupported validation target" ;;
esac

candidate_identity="candidate=$candidate_version"
target_identity="$target_os/$target_arch"
stage="host-identity"

command -v uname >/dev/null 2>&1 || fail "required host identity tool is unavailable: uname"
case "$(uname -s)" in
  Darwin) host_os="darwin" ;;
  Linux) host_os="linux" ;;
  *) host_os="unsupported" ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) host_arch="arm64" ;;
  x86_64 | amd64) host_arch="amd64" ;;
  *) host_arch="unsupported" ;;
esac

if [ "$host_os/$host_arch" != "$target_os/$target_arch" ]; then
  fail "native host does not match the required target"
fi
passed

stage="candidate-identity"
[ -d "$candidate_directory" ] || fail "candidate directory is unavailable"
candidate_directory="$(cd "$candidate_directory" && pwd -P)" || fail "candidate directory could not be resolved"
script_directory="$(CDPATH= cd "$(dirname "$0")" && pwd -P)" || fail "validator location could not be resolved"
repository_directory="$(dirname "$script_directory")"
cd "$repository_directory" || fail "repository directory could not be opened"
command -v go >/dev/null 2>&1 || fail "required validation tool is unavailable: go"
if ! go run ./tools/releaseverify --dist "$candidate_directory" --version "$candidate_version"; then
  fail "candidate identity or artifact set is invalid"
fi
passed

stage="controlled-endpoint"
for prerequisite in cp mktemp rm sh; do
  command -v "$prerequisite" >/dev/null 2>&1 || fail "required validation tool is unavailable"
done
real_cp="$(command -v cp)" || fail "copy tool could not be resolved"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/acs-promoted.XXXXXX")" || fail "validation workspace could not be created"
workspace="$(cd "$workspace" && pwd -P)" || fail "validation workspace could not be resolved"
cleanup() {
  rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM
tools_directory="$workspace/tools"
temporary_directory="$workspace/tmp"
custom_home="$workspace/custom-home"
default_home="$workspace/default-home"
mkdir "$tools_directory" "$temporary_directory" "$custom_home" "$default_home" || fail "validation workspace could not be prepared"
chmod 0700 "$tools_directory" "$temporary_directory" "$custom_home" "$default_home" || fail "validation workspace could not be secured"
url_log="$workspace/urls"
release_url="https://github.com/alcimerio/ai-config-selector/releases/download/${candidate_version}"

cat >"$tools_directory/curl" <<'EOF'
#!/bin/sh
set -eu
output=""
url=""
saw_fail=0
saw_location=0
saw_https=0
saw_tls=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fail) saw_fail=1; shift ;;
    --location) saw_location=1; shift ;;
    --proto)
      [ "$#" -ge 2 ] && [ "$2" = "=https" ] || exit 64
      saw_https=1
      shift 2
      ;;
    --tlsv1.2) saw_tls=1; shift ;;
    --output)
      [ "$#" -ge 2 ] || exit 64
      output="$2"
      shift 2
      ;;
    --*) exit 64 ;;
    *)
      [ -z "$url" ] || exit 64
      url="$1"
      shift
      ;;
  esac
done
[ "$saw_fail" -eq 1 ] && [ "$saw_location" -eq 1 ] && [ "$saw_https" -eq 1 ] && [ "$saw_tls" -eq 1 ] || exit 64
[ -n "$output" ] && [ -n "$url" ] || exit 64
base="$ACS_PROMOTED_RELEASE_URL/"
case "$url" in
  "$base"*) name="${url#"$base"}" ;;
  *) exit 64 ;;
esac
case "$name" in
  "$ACS_PROMOTED_ARCHIVE" | SHA256SUMS) ;;
  *) exit 64 ;;
esac
[ "$url" = "$base$name" ] || exit 64
printf '%s\n' "$name" >>"$ACS_PROMOTED_URL_LOG"
exec "$ACS_PROMOTED_REAL_CP" "$ACS_PROMOTED_CANDIDATE_DIRECTORY/$name" "$output"
EOF
chmod 0700 "$tools_directory/curl" || fail "controlled endpoint could not be secured"
passed

archive_name="acs_${archive_version}_${target_os}_${target_arch}.tar.gz"
run_installer() {
  selected_home="$1"
  selected_path="$2"
  output_path="$3"
  shift 3
  env \
    ACS_PROMOTED_ARCHIVE="$archive_name" \
    ACS_PROMOTED_CANDIDATE_DIRECTORY="$candidate_directory" \
    ACS_PROMOTED_REAL_CP="$real_cp" \
    ACS_PROMOTED_RELEASE_URL="$release_url" \
    ACS_PROMOTED_URL_LOG="$url_log" \
    HOME="$selected_home" \
    PATH="$tools_directory:$selected_path" \
    TMPDIR="$temporary_directory" \
    sh "$candidate_directory/install.sh" "$@" >"$output_path" 2>&1
}

stage="custom-install"
if ! run_installer "$custom_home" "$PATH:$install_directory" "$workspace/custom-output" --bin-dir "$install_directory"; then
  fail "release-specific installer rejected the supplied candidate"
fi
[ -x "$install_directory/acs" ] || fail "installed executable is unavailable or not executable"
if [ "$("$install_directory/acs" version 2>/dev/null)" != "acs $candidate_version" ]; then
  fail "installed executable reported an unexpected version"
fi
[ -z "$(find "$temporary_directory" -mindepth 1 -print -quit)" ] || fail "installer left temporary state after custom installation"
passed

stage="default-install"
if ! run_installer "$default_home" "$PATH" "$workspace/default-output"; then
  fail "release-specific installer rejected its default destination"
fi
[ -x "$default_home/.local/bin/acs" ] || fail "default installed executable is unavailable or not executable"
if ! grep -F "Add ACS to PATH for this shell with:" "$workspace/default-output" >/dev/null 2>&1; then
  fail "default installation omitted PATH guidance"
fi
for startup_file in .profile .bashrc .bash_profile .zshrc; do
  [ ! -e "$default_home/$startup_file" ] || fail "installer modified shell startup state"
done
[ -z "$(find "$temporary_directory" -mindepth 1 -print -quit)" ] || fail "installer left temporary state after default installation"
passed

stage="installer-selection"
cat >"$workspace/expected-urls" <<EOF
$archive_name
SHA256SUMS
$archive_name
SHA256SUMS
EOF
if ! cmp -s "$workspace/expected-urls" "$url_log"; then
  fail "installer did not select the exact pinned candidate assets"
fi
passed

stage="complete"
passed

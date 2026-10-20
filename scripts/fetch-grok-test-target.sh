#!/bin/sh

set -eu
set -f
LC_ALL=C
export LC_ALL

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: scripts/fetch-grok-test-target.sh <lock-file> <output-archive>" >&2
  exit 2
fi

lock_file="$1"
output_path="$2"

fail() {
  printf 'fetch Grok test target: %s\n' "$1" >&2
  exit 1
}

[ -f "$lock_file" ] && [ ! -L "$lock_file" ] || fail "lock file is unavailable or unsafe"
[ ! -e "$output_path" ] && [ ! -L "$output_path" ] || fail "output path already exists"
output_directory="$(dirname "$output_path")"
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || fail "output directory is unavailable or unsafe"

url=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ""|\#*) continue ;;
  esac
  case "$line" in
    "1.0.62|linux|amd64|"*)
      url="${line#1.0.62|linux|amd64|}"
      url="${url#*|}"
      ;;
  esac
done < "$lock_file"
case "$url" in
  https://x.ai/cli/grok-1.0.62-linux-x86_64.zst) ;;
  *) fail "lock URL is not the reviewed linux/amd64 artifact" ;;
esac

curl -fsSL --retry 3 --retry-delay 2 -o "$output_path" "$url" || fail "download failed"
[ -f "$output_path" ] && [ ! -L "$output_path" ] || fail "download is not a regular file"

#!/usr/bin/env bash
# Time a few real acs commands on this machine.
# Usage: scripts/bench-commands.sh /path/to/acs
# Optional: RUNS=15 (default). Prints one median and sample standard deviation
# per command, in milliseconds. Failures are reported and abort the run.

set -euo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
	echo "usage: $0 /path/to/acs" >&2
	exit 2
fi

ACS=$1
RUNS=${RUNS:-15}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOME_DIR=$ROOT/home
EMPTY=$ROOT/base/empty
BIG=$ROOT/base/repo
mkdir -p "$HOME_DIR/.acs/profiles" "$EMPTY" "$BIG"
install -m 0600 "$REPO/examples/profiles/sandbox-tools-only.json" "$HOME_DIR/.acs/profiles/sandbox-tools-only.json"
export HOME=$HOME_DIR

python3 - "$BIG" <<'PY'
import os, sys
root = sys.argv[1]
for index in range(4000):
    directory = os.path.join(root, f"d{index // 40}")
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, f"f{index}.txt"), "w", encoding="utf-8") as handle:
        handle.write("x")
PY

time_cmd() {
	local name=$1
	local dir=$2
	shift 2
	local samples=()
	local i start end
	for ((i = 0; i < RUNS; i++)); do
		start=$(date +%s%N)
		if ! (cd "$dir" && "$@" </dev/null >/dev/null 2>"$ROOT/err"); then
			echo "$name failed:" >&2
			cat "$ROOT/err" >&2
			exit 1
		fi
		end=$(date +%s%N)
		samples+=("$(( (end - start) / 1000000 ))")
	done
	python3 - "$name" "${samples[@]}" <<'PY'
import math, sys
name, *samples = sys.argv[1:]
values = [int(sample) for sample in samples]
values.sort()
count = len(values)
median = values[count // 2] if count % 2 else (values[count // 2 - 1] + values[count // 2]) / 2
mean = sum(values) / count
variance = sum((value - mean) ** 2 for value in values) / (count - 1) if count > 1 else 0
print(f"{name}: median {median:g} ms  pstdev {math.sqrt(variance):.1f} ms  n={count}  samples={values}")
PY
}

time_cmd "version" "$EMPTY" "$ACS" version
time_cmd "profile list" "$EMPTY" "$ACS" profile list
time_cmd "explain sandbox" "$EMPTY" "$ACS" explain sandbox --profile sandbox-tools-only
time_cmd "sandbox --dry-run" "$EMPTY" "$ACS" sandbox --dry-run --profile sandbox-tools-only
time_cmd "run /bin/true empty" "$EMPTY" "$ACS" run --profile sandbox-tools-only -- /bin/true
time_cmd "run /bin/true 4000 files" "$BIG" "$ACS" run --profile sandbox-tools-only -- /bin/true

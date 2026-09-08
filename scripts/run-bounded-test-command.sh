#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 || ! "$1" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: run-bounded-test-command.sh SECONDS COMMAND [ARG ...]" >&2
  exit 2
fi

deadline_seconds="$1"
shift
progress_seconds="${ACS_BOUNDED_TEST_PROGRESS_SECONDS:-15}"
if [[ ! "$progress_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid bounded test progress interval" >&2
  exit 2
fi
output="$(mktemp "${TMPDIR:-/tmp}/acs-bounded-test.XXXXXX")"
start_gate="${output}.start"
: >"$start_gate"
emitted_lines=0
command_pid=""
command_pgid=""
private_group_verified=0

emit_completed_lines() {
  local current_lines
  current_lines="$(wc -l <"$output" | tr -d '[:space:]')"
  if (( current_lines > emitted_lines )); then
    sed -n "$((emitted_lines + 1)),${current_lines}p" "$output"
    emitted_lines=$current_lines
  fi
}

emit_remainder() {
  tail -n "+$((emitted_lines + 1))" "$output"
}

stop_private_group() {
  local process_group="$1"
  if kill -0 -- "-${process_group}" 2>/dev/null; then
    kill -TERM -- "-${process_group}" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-${process_group}" 2>/dev/null || true
  fi
}

cleanup_on_exit() {
  status=$?
  trap - EXIT
  set +e
  if [[ -n "$command_pid" ]] && kill -0 "$command_pid" 2>/dev/null; then
    if (( private_group_verified )); then
      stop_private_group "$command_pgid"
    else
      # The payload is still gated on every pre-verification exit, so the
      # direct child cannot yet have created payload descendants.
      kill -KILL "$command_pid" 2>/dev/null
      wait "$command_pid" 2>/dev/null
    fi
  fi
  rm -f "$output" "$start_gate"
  exit "$status"
}

trap cleanup_on_exit EXIT

# Bash job control gives the background command its own process group even in
# this non-interactive shell. Verify that identity before any group-directed
# signal so a diagnostic timeout can never address the Actions runner's group.
# The private child waits behind a file gate so even a fast command cannot exit
# before that identity check is complete.
set -m
(
  while [[ -e "$start_gate" ]]; do
    sleep 0.05
  done
  exec "$@"
) >"$output" 2>&1 &
command_pid=$!
set +m

set +e
command_pgid="$(ps -o pgid= -p "$command_pid" 2>/dev/null | tr -d '[:space:]')"
group_status=$?
shell_pgid="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d '[:space:]')"
shell_group_status=$?
set -e
if (( group_status != 0 || shell_group_status != 0 )) || [[ -z "$command_pgid" || -z "$shell_pgid" || "$command_pgid" != "$command_pid" || "$command_pgid" == "$shell_pgid" ]]; then
  kill -TERM "$command_pid" 2>/dev/null || true
  (
    sleep 3
    kill -KILL "$command_pid" 2>/dev/null || true
  ) &
  cleanup_pid=$!
  set +e
  wait "$command_pid"
  set -e
  kill "$cleanup_pid" 2>/dev/null || true
  set +e
  wait "$cleanup_pid" 2>/dev/null
  set -e
  emit_remainder
  echo "bounded test command did not receive a private process group" >&2
  exit 2
fi
private_group_verified=1
rm -f "$start_gate"

started=$SECONDS
next_progress=$progress_seconds
while kill -0 "$command_pid" 2>/dev/null; do
  elapsed=$((SECONDS - started))
  if (( elapsed >= next_progress )); then
    echo "bounded test command progress: ${elapsed}s elapsed" >&2
    emit_completed_lines
    next_progress=$((next_progress + progress_seconds))
  fi
  if (( elapsed >= deadline_seconds )); then
    echo "bounded test command exceeded ${deadline_seconds}s; requesting Go stacks" >&2
    emit_completed_lines
    kill -QUIT -- "-${command_pgid}" 2>/dev/null || true
    sleep 3
    emit_completed_lines
    kill -TERM -- "-${command_pgid}" 2>/dev/null || true
    sleep 2
    kill -KILL -- "-${command_pgid}" 2>/dev/null || true
    set +e
    wait "$command_pid"
    set -e
    emit_remainder
    exit 124
  fi
  sleep 1
done

set +e
wait "$command_pid"
status=$?
set -e
stop_private_group "$command_pgid"
emit_remainder
exit "$status"

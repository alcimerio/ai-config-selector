#!/bin/sh
# Sourced by the fetcher and installer. Validate the entire lock before any I/O.
validate_codex_lock() {
  arm64_digest=; host_digest=
  count=0
  old_cli=0; old_host=0; new_cli=0; new_host=0
  while IFS= read -r physical_row || [ -n "$physical_row" ]; do
    [ -n "$physical_row" ] || fail "lock contains a blank row"
    case "$physical_row" in '#'* ) continue ;; esac
    delimiters="$(printf '%s' "$physical_row" | tr -cd '|')"
    [ "${#delimiters}" -eq 4 ] || fail "lock entry has an unexpected field count"
    IFS='|' read -r version target_os target_arch digest url <<EOF
$physical_row
EOF
    [ -n "$version" ] && [ -n "$target_os" ] && [ -n "$target_arch" ] && [ -n "$digest" ] && [ -n "$url" ] || fail "lock entry is incomplete"
    case "$version:$target_os" in 0.149.1:darwin|0.156.0:darwin) ;; *) fail "lock entry has an unsupported target" ;; esac
    case "$target_arch:$url" in
      "arm64:https://github.com/openai/codex/releases/download/rust-v$version/codex-aarch64-apple-darwin.tar.gz") role=cli ;;
      "arm64:https://github.com/openai/codex/releases/download/rust-v$version/codex-code-mode-host-aarch64-apple-darwin.tar.gz") role=host ;;
      *) fail "lock entry does not name an approved release asset" ;;
    esac
    [ "${#digest}" -eq 64 ] || fail "lock entry has an invalid SHA-256 digest"
    case "$digest" in *[!0-9a-f]*) fail "lock entry has an invalid SHA-256 digest" ;; esac
    case "$version:$role" in
      0.149.1:cli) old_cli=$((old_cli+1)) ;;
      0.149.1:host) old_host=$((old_host+1)) ;;
      0.156.0:cli) new_cli=$((new_cli+1)) ;;
      0.156.0:host) new_host=$((new_host+1)) ;;
    esac
    if [ "$version" = "${selected_version:-}" ]; then
      case "$role" in cli) arm64_digest="$digest" ;; host) host_digest="$digest" ;; esac
    fi
    count=$((count+1))
  done <"$lock_file"
  case "$old_cli:$old_host" in 0:0|1:1) ;; *) fail "lock must contain exactly one CLI and one code-mode host per version" ;; esac
  case "$new_cli:$new_host" in 0:0|1:1) ;; *) fail "lock must contain exactly one CLI and one code-mode host per version" ;; esac
  [ "$count" -gt 0 ] || fail "lock contains no targets"
}

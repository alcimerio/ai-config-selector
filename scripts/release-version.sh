#!/bin/sh

# Shared release-tag contract for repository maintenance scripts. Release tags
# have exactly three ASCII decimal components, with no leading zeroes, preceded
# by v. Prerelease and build suffixes are not release tags. Do not use arithmetic:
# canonical components are not limited to the host shell's integer range.
#
# This predicate emits nothing and does not change the caller's variables,
# positional arguments, IFS, locale, or shell options.
acs_is_release_version() (
  [ "$#" -eq 1 ] || return 1
  case "$1" in
    v*.*.*) version="${1#v}" ;;
    *) return 1 ;;
  esac

  # Parameter expansion preserves empty components, including a trailing dot.
  # Any extra separator remains in patch and fails the ASCII digit check.
  major="${version%%.*}"
  minor_patch="${version#*.}"
  minor="${minor_patch%%.*}"
  patch="${minor_patch#*.}"
  for component in "$major" "$minor" "$patch"; do
    case "$component" in
      '' | *[!0123456789]* | 0?*) return 1 ;;
    esac
  done
  return 0
)

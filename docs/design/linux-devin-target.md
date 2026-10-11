# Experimental Linux Devin qualification (#190)

[Documentation index](../README.md)

This implements the amd64 inputs and qualification harness for
[roadmap item 12](linux-support.md#stack-5--targets). Production Linux admission
remains closed. There is no Linux backend registration or production helper
entry point. Linux arm64 is explicitly deferred; its presence in the upstream
manifest does not create an ACS lock row or support claim. macOS behavior and
its native gates are unchanged.

## Published bytes and runtime bundle

On 2026-10-10, the exact
[3000.10.21 publisher manifest](https://static.devin.ai/cli/3000.10.21/manifest.json)
and [Linux amd64 archive](https://static.devin.ai/cli/3000.10.21/devin-3000.10.21-x86_64-unknown-linux.tar.gz)
were downloaded over HTTPS. The archive digest matched the publisher's
`x86_64-unknown-linux` entry. The unmodified manifest is retained in
`scripts/testdata/devin-3000.10.21-manifest.json`; its SHA-256 is
`b070658dcb6a7a4ed753cdd9b453375118aea1bf5ed3d353dbbbabc627f2d12c`.

| Input | SHA-256 |
| --- | --- |
| Linux amd64 archive | `7cac6f5739ba3a3e5542f3b7fa07ed902d6dfb96ca22e4c63ae84c03bb7db47c` |
| Extracted `bin/devin` (180,863,528 bytes) | `ba1956450c0e0bf95f477ccd442a0b45b14765402b2377d6737ae758126d70cd` |

ELF inspection of those bytes finds an amd64 static PIE: no `PT_INTERP`, no
`DT_NEEDED`, and no RPATH/RUNPATH. The other archive members are documentation
and man pages, not runtime dependencies of the qualification probes. The
experimental recipe binds only the checked executable; it does not expose the
installation tree, `/usr`, host libraries or host home. The ordinary command
recipe retains its 64 MiB bound. Only the digest-checked Devin path accepts this
larger executable. The recipe resolves an explicit absolute executable path,
checks its type, size, permissions, ELF metadata and SHA-256, then carries the
captured identity into the existing mount pinning checks.

`scripts/devin-test-targets.lock` records the archive; the sibling
`devin-test-target-files.lock` records the sole runtime member. The installer
selects the native OS/architecture row, rejects duplicates, unsafe archive paths
and nonregular/duplicate target members, and verifies both digests before
installing mode 0500. It retains the verified archive for inspection. Linux
installation does not execute the target: version and behavior checks run in the
contained native harness. The existing macOS version check remains in place.

## Credential, Skills and MCP checks

The test-only recipe accepts `--version`, `auth status`, `skills list --json`
and `mcp list`. It supplies private HOME and XDG config/data/cache/state paths
through the sealed environment. It accepts neither arbitrary Devin flags nor
interactive launch.

The native harness uses the pinned executable and synthetic, invalid credentials
from the existing acceptance fixture. Each probe gets a fresh protected Session,
system Bubblewrap, Landlock, seccomp, delegated cgroup placement and authenticated
settlement before removal. It checks:

- Absent credentials versus the exact 0600
  `home/.local/share/devin/credentials.toml`; unrelated host XDG credentials do
  not supply authentication. The executor's source allowlist remains exactly
  `.local/share/devin/credentials.toml` under its supplied existing home; no XDG
  source fallback or host migration directories are copied.
- Both selected global Skill sources (`.config/devin/skills` and
  `.agents/skills`) against the shared exact catalog interpreter, with an
  unselected host catalog outside the runtime view.
- Selected user MCP discovery with host MCP configuration hidden, plus readable
  project MCP positive controls and explicit existing-file exclusions.
- The reported version, no credential payload in probe output, and complete
  process settlement before Session removal. Failed helpers retain their
  temporary root for inspection.

These MCP discovery tests do not establish immutable configuration or global
reserved-basename enforcement. The filesystem compiler still refuses the full
production Devin MCP protection request, including selected config protection
inside writable HOME. It is not weakened to make these tests pass.

## Running the checks and evidence limits

```sh
target_root=$(mktemp -d)
mkdir "$target_root/bin"
scripts/install-devin-test-target.sh scripts/devin-test-targets.lock "$target_root" "$target_root/bin/devin"
ACS_TEST_DEVIN_BINARY="$target_root/bin/devin" CGO_ENABLED=0 go test ./internal/launch -run '^TestLinuxDevinPublishedBytes$' -v
ACS_LINUX_NATIVE_REQUIRED=1 ACS_TEST_DEVIN_BINARY="$target_root/bin/devin" CGO_ENABLED=0 go test ./internal/launch -run '^TestLinuxNativeDevinPreflights$' -v -count=1
```

The native suite checks Ubuntu 24.04, kernel 6.12+, amd64, system Bubblewrap,
Landlock/seccomp, namespaces and cgroup delegation, and refuses WSL/containers.
Missing prerequisites or a missing installed target skip only when
`ACS_LINUX_NATIVE_REQUIRED` is unset; required runs fail. Digest/behavior failures
are always failures. Installation alone is not host qualification.

At implementation time, downloaded archive/member digests and actual ELF
metadata passed. Unit tests exercise installer failure paths, locked target
rejection, private XDG transport and the unchanged credential allowlist using
mocked process observations. The full native target suite skipped on the
development host because its distribution, Bubblewrap and delegation prerequisites
were unavailable; no native Devin authentication, Skills, MCP or whole-Session
conformance is claimed from that run.

Remaining gates include native Ubuntu HWE execution of this suite, broader
interactive/network/runtime qualification, protected MCP configuration and
basename semantics, and immutable executable contents across preparation and
execution (identity pinning alone does not freeze same-inode writes). No release,
credential-provider change, arm64 qualification or egress filtering is included.

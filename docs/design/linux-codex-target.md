# Experimental Linux Codex pairs (#190)

[Documentation index](../README.md)

This implements the lock, fixed recipe and qualification harness for
[roadmap item 13](linux-support.md#stack-5--targets). Production Linux admission
remains closed. No backend registration, production helper, user bypass, release
matrix change or Linux arm64 admission is added. Darwin keeps its existing lock,
version probe, recipes and tests.

## Exact inputs

The two reviewed versions remain 0.149.1 and 0.156.0. On 2026-10-10, the CLI and
code-mode-host `x86_64-unknown-linux-musl.tar.gz` assets were downloaded from the
official [0.149.1 release](https://github.com/openai/codex/releases/expanded_assets/rust-v0.149.1)
and [0.156.0 release](https://github.com/openai/codex/releases/expanded_assets/rust-v0.156.0).
All four archive SHA-256 digests matched GitHub's published release-asset digests.
`scripts/codex-linux-test-targets.lock` records those exact URLs and digests,
separately from the unchanged macOS lock.

The extracted members are also locked in `internal/codexcompat/linux_target.go`:

| Version | Member | Bytes | SHA-256 |
| --- | --- | --- | --- |
| 0.149.1 | CLI | 258227840 | `73dc5888888f411c1f0fa7b81d866e721dcc86b527ce8e3b2cf4708661e823ba` |
| 0.149.1 | Companion | 57886648 | `48f3a0d48033039cc7caccd209edb0ee350b81f82ca851a7b129e146e4bec6fb` |
| 0.156.0 | CLI | 284361064 | `78a11f06e0a2dda42d13fba1d50dc62e8cbdb2d5f69789722f4d4d99b5cdbe30` |
| 0.156.0 | Companion | 70644624 | `a5c727845f8418acfe5a3d0ff05ad892d76545e51834da817cf77d6d83bdeb18` |

ELF inspection finds static amd64 PIEs without `PT_INTERP`, `DT_NEEDED`, RPATH or
RUNPATH. The runtime binds only the CLI and its same-version sibling companion.
It rejects missing, modified, cross-version, writable or multiply linked files,
and companion symlink substitution. It never executes `--version` to decide
which bytes are trusted, searches PATH, imports a package directory, or uses
Codex's bundled Bubblewrap. The generic 64 MiB executable limit remains intact.

The shared fetcher validates one platform per lock and complete pairs before
downloads. The installer verifies both archive digests and exact regular members
before publishing either mode-0500 file. Linux installation executes neither
member; the existing macOS version check remains unchanged.

## Recipe, credentials and refusals

The experimental recipe fixes file-only auth, ChatGPT login/workspace, provider,
endpoint, external ACS sandboxing, no target approval prompts, untrusted project
configuration, disabled plugins/apps and empty MCP selection. It accepts only
version, device login, status, MCP inventory and interactive startup operations.
Extra flags, config overrides, custom endpoints, arbitrary subcommands and
selected environment variables are refused. HOME and XDG paths come from the
sealed Session environment, excluding host auth, desktop buses and API tokens.

`CODEX_HOME` is explicitly fixed to the Session's `.codex` directory. The
launcher overlays its `config.toml` with sealed, generated empty-selection bytes
using Bubblewrap's read-only data mount, leaving authentication refreshes and
other Session state writable. Original Session config bytes remain unchanged.
Captured project and ancestor `.codex/config.toml` paths are omitted from the
private filesystem, including absent names that could otherwise appear in live
directory binds. Writable workspace authority that conflicts with these
exclusions is refused by the existing compiler.

This projection is necessary because Codex's
[configuration merge](https://github.com/openai/codex/blob/rust-v0.149.1/codex-rs/config/src/merge.rs)
recursively merges tables: `-c mcp_servers={}` does not erase lower-layer servers.
The [configuration loader](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/config/src/loader/mod.rs)
also discovers project config independently of the user config directory.

The stack-4 file provider requires durable explicit selection and keeps its
existing `$XDG_STATE_HOME/acs/credentials` storage (default
`~/.local/state/acs/credentials`). Only the selected identity is projected into
the Session as mode-0600 `.codex/auth.json`. Provider absence, unavailable Secret
Service or a missing named identity never selects global Codex auth or creates
an implicit plaintext provider.

The filesystem compiler still refuses arbitrary selected immutable MCP
configuration/recipe files under writable Session HOME. The fixed generated
empty-selection overlay does not enable that deferred feature. A regression
test supplies both protections and asserts refusal, with an unprotected positive
compilation control. This is a
closed admission gate, not evidence of native immutable-MCP support. No
protection is removed to make this recipe launch.

## Tests and evidence

```sh
target_root=$(mktemp -d)
scripts/fetch-codex-test-targets.sh scripts/codex-linux-test-targets.lock "$target_root/archives"
for codex_version in 0.149.1 0.156.0; do
  mkdir "$target_root/$codex_version"
  scripts/install-codex-test-target.sh scripts/codex-linux-test-targets.lock \
    "$target_root/archives" amd64 "$target_root/$codex_version/codex" "$codex_version"
done
ACS_TEST_CODEX_LINUX_ROOT="$target_root" CGO_ENABLED=0 go test ./internal/launch -run '^TestLinuxCodexPublishedPairs$' -v
ACS_LINUX_NATIVE_REQUIRED=1 ACS_TEST_CODEX_LINUX_ROOT="$target_root" CGO_ENABLED=0 go test ./internal/launch -run '^TestLinuxNativeCodexPairs$' -v -count=1
```

The native harness requires Ubuntu 24.04, kernel 6.12+, amd64, system Bubblewrap,
Landlock, seccomp, namespaces and delegated cgroup v2, refusing WSL/containers.
Every probe must obtain authenticated full-Session settlement before deletion or
credential finalization. Failed helpers retain their state. Missing prerequisites
skip only without `ACS_LINUX_NATIVE_REQUIRED`; required runs fail.

For each pair the harness asserts real contained version output, absent versus
selected synthetic-identity status, suppressed project/Session MCP configuration,
and credential-free terminal startup, resize and termination. The synthetic login
seed is explicitly a no-child provider transaction. Unit tests use the real file
provider, locks, private snapshots, projections and durable quarantine with mocked
target login/status/interactive behavior, refresh and missing settlement evidence.
They also cover identity substitution, unavailable providers and global-auth
refusal. These mocks do not establish kernel containment or upstream login/model
behavior.

On the development host, downloaded archive/member verification, ELF inspection,
actual installation and unit checks passed. The whole native launch suite skipped
for missing Ubuntu/system-Bubblewrap/delegation prerequisites; required-native
mode failed as intended. Native Linux Codex login, model/tool interaction,
companion execution, protected MCP mutation denial, online runtime inputs and
credential quarantine after real supervisor loss remain qualification gates.
Identity pinning also does not freeze same-inode host writes through execution;
production composition with the shared private executable snapshots still needs
native proof. No Linux support or egress-filtering claim follows from these tests.

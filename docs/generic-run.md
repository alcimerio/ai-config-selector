# Run a generic command

The current development source supports one explicit command through the same
ACS-owned Session, common Profile authority, native sandbox, attachment, and
cleanup machinery as registered targets:

```sh
acs run --profile backend-review -- /usr/bin/git status
acs run --dry-run --profile backend-review -- ./scripts/check --format "short summary"
acs run --profile backend-review -- /usr/bin/git diff -- "path with spaces"
```

Exactly one `--` separates ACS flags from the child argv. `--profile NAME` and
`--dry-run` may be reordered before that boundary and may each occur once.
Everything after the boundary is literal: spaces and empty strings remain in
their individual argv elements, leading dashes stay child arguments, and a
later `--` is not parsed by ACS. A command is required. Unknown ACS flags,
duplicate flags, NUL, another separator in command position, and missing or
ambiguous executable forms fail before Profile discovery or runtime setup.

ACS never inserts a shell. Shell expressions, pipelines, redirections, glob
patterns, aliases, and variable references are passed as ordinary bytes to the
selected executable and are not evaluated. Invoke a shell explicitly only if
that shell itself is the command you intend to contain.

## Executable resolution

Bare executable names search exactly `/usr/local/bin:/usr/bin:/bin`, in that
order. The invoking process `PATH` is ignored. Use an absolute path for any
tool outside that list, including a Homebrew tool installed elsewhere.
Absolute executable paths begin with `/`. A workspace-relative executable must
begin with `./`; its canonical target must remain inside the canonical current
workspace. Other relative paths containing `/` are rejected.

Planning and execution apply the same regular-file and executable checks. A
real run captures the resolved path and file identity, then resolves and checks
them again after Session materialization and immediately before native sandbox
preparation. Ordinary symlink retargeting, replacement, modification, or
working-directory drift therefore fails closed. This narrows the replacement
window but is not a claim that path-based execution provides an atomic kernel
file-identity guarantee.

## Profile, environment, and grants

Generic execution selects no target overlay and no named authentication. For
v3 Profiles it materializes selected common Skills only under
`$HOME/.acs/common/v1/skills/<source>/<relative-path>` in the synthetic Session
home. Inactive Devin, Codex, and unknown overlay payloads stay inert. Legacy
v1/v2 Profiles retain their established writable workspace and legacy Skill
placement; a v3 Profile defaults to read-only unless the user explicitly chose
coding write.

The current sandbox grants only the resolved Profile workspace authority, the
private writable Session, and intrinsic access needed to execute the selected
file. It does not infer a filesystem or network grant catalog from child
arguments. Target full-permission or YOLO flags cannot weaken the outer ACS
sandbox. The child receives synthetic `HOME`, XDG and temporary directories;
the fixed PATH above; and only validated terminal/locale variables. Arbitrary
host configuration, credentials, environment variables, descriptors, and
named target authentication are not inherited.

Standard descriptors 0, 1, and 2 preserve terminal, pipe, and shell-level
redirection connections. Alternate supplied files must be actual PTYs under
the shared descriptor contract. Foreground-terminal and resize behavior is
active only for a foreground TTY input. ACS forwards termination signals to
the contained process group and retains or quarantines the Session whenever
descendant cleanup is not proven.

## Dry-run, exits, and recovery

`--dry-run` validates the stored Profile, selected Skill sources, executable
intent and identity, and reports the existing bounded native-backend readiness
probe. That ACS-owned probe may execute the fixed system backend readiness
helper; it is distinct from the requested command. Dry-run creates no Session,
reads no credential, starts no user command or target preflight, and writes no
file. Its deterministic plan hides absolute source/executable paths and all
argument values.

Normal exits preserve the command status; signals map to `128 + signal`.
Cancellation maps to 130 only after cleanup is proven. Sandbox, lifecycle, or
unproven-cleanup failures map to 1 and use redacted categories. Each successful
Start has exactly one Wait attempt. If cleanup cannot be confirmed, ACS keeps
the Session protected for startup recovery rather than deleting live state.

The supported runtime is macOS 26 on Apple Silicon. Source identity and the
exact supplied candidate tested by CI define this development feature; it is
not attributed to an older published release. Separate multi-project real-use
observations remain outside this delivery.

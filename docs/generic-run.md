# Run a generic command

[Documentation index](README.md) · [Common Profile grants](common-profile-format.md)

ACS supports one explicit command through the same
ACS-owned Session, common Profile authority, native sandbox, attachment, and
cleanup machinery as registered targets:

```sh
acs run --profile backend-review -- /usr/bin/git status
acs run --dry-run --profile backend-review -- ./scripts/check --format "short summary"
acs run --profile backend-review -- /usr/bin/git diff -- "path with spaces"
```

Exactly one `--` separates ACS flags from the child argv. `--profile NAME` and
`--dry-run` may be reordered before that boundary and may each occur once.
The optional `--expect-authority-digest DIGEST` also belongs before the boundary;
it refuses a run whose semantic authority differs from a previously reviewed
[effective-capability explanation](diagnostics.md#effective-capability-explanation).
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
v3 Profiles it materializes selected common Skills under
`$HOME/.acs/common/v1/skills/<source>/<relative-path>` and explicitly selected
instruction files under `$HOME/.acs/common/v1/instructions/<source>/<relative-path>`
in the synthetic Session home. It does not create Devin rules paths or apply
Devin activation semantics. It neither projects target MCP configuration nor
automatically starts selected MCP servers; their separately selected common
resource grants still apply. Inactive Devin, Codex, and unknown overlay
payloads stay inert. Legacy
v1/v2 Profiles retain their established writable workspace and legacy Skill
placement; a v3 Profile defaults to read-only unless the user explicitly chose
coding write.

The sandbox applies the resolved Profile workspace authority, explicitly
selected `common.paths` and `common.executables` grants, the private writable
Session, and bounded intrinsic runtime access. Executable grants add file
visibility; they are not an exclusive command allowlist. A read-only workspace
does not make separately selected external paths read-only. ACS
does not infer a filesystem or network grant catalog from child arguments. Target full-permission or YOLO flags cannot weaken the outer ACS
sandbox. The child receives synthetic `HOME`, XDG and temporary directories;
the fixed PATH above; validated terminal/locale variables; and any explicitly
selected v3 `common.environment` destinations. Those values are freshly
resolved before Session creation and apply to the attached command and its
descendants only. Unselected host configuration, credentials, environment
variables, descriptors, and named target authentication are not inherited.
Selected environment references can include secrets, so a generic command is
not necessarily secret-free merely because no target authentication is
projected. All attached descendants share those selected environment values.
Selected environment transport requires the supported macOS runtime. Unsupported
hosts fail closed before Session creation.

Outbound IP connections and macOS DNS access remain coarse intrinsic authority.
ACS is not an egress firewall: it does not enforce destination allowlists or
prevent a command from transmitting files or values it can read. Selecting a
filesystem read-only grant limits writes, not network transmission.

Standard descriptors 0, 1, and 2 preserve terminal, pipe, and shell-level
redirection connections. Alternate supplied files must be actual PTYs under
the shared descriptor contract. Foreground-terminal and resize behavior is
active only for a foreground TTY input. ACS forwards termination signals to
the contained process group and retains or quarantines the Session whenever
descendant cleanup is not proven.

## Dry-run, exits, and recovery

`--dry-run` validates the stored Profile, resolves selected Skill and
instruction sources, validates the literal command executable intent and
identity, and reports the existing bounded native-backend readiness
probe. That ACS-owned probe may execute the fixed system backend readiness
helper; it is distinct from the requested command. Dry-run creates no Session,
reads no credential, starts no user command or target preflight, and writes no
file. Its deterministic plan hides absolute source/executable paths and all
argument values. It does not resolve selected environment values or prove
that all runtime path/executable grants will still be available at launch.

Normal exits preserve the command status; signals map to `128 + signal`.
Cancellation maps to 130 only after cleanup is proven. Sandbox, lifecycle, or
unproven-cleanup failures map to 1 and use redacted categories. Each successful
Start has exactly one Wait attempt. If cleanup cannot be confirmed, ACS keeps
the Session protected for startup recovery rather than deleting live state.
Use the [Session operations guide](session-operations.md) to inspect and recover
retained state; do not remove private Session or lease files by hand.

The supported runtime is macOS 26 on Apple Silicon.

# Passive diagnostics and Profile validation

These commands describe the development source, not the published v0.4.0 binary.

```sh
acs doctor
acs doctor --target devin --json
acs doctor --json --target sandbox
acs doctor --target codex-auth
acs profile validate backend-review
acs profile validate --json backend-review
```

`doctor` checks core host/platform and native backend-file prerequisites without
requiring HOME, an account, a terminal, or optional clients. Supported hosts are
macOS 26 on arm64 or Intel. Linux and other platforms fail the platform check;
no Linux support is implied. macOS product version comes from the native
`kern.osproductversion` API, without executing `sw_vers`.

An optional `--target` requests just that workflow's executable availability:
`devin` searches for `devin`, `sandbox` checks `/bin/zsh`, and `codex-auth` searches
for `codex`. The last describes the implemented named Codex authentication
workflows; interactive Codex launch is not implemented. This option is not a
sandbox-backend selector. Only absolute PATH entries are searched; empty or
relative entries are ignored. Executables must resolve to readable, executable
regular files; symlinks to such files follow existing runtime lookup semantics.
Presence does not establish version compatibility, including the existing
`codex-cli 0.149.1` login/status requirement.

Backend availability checks only the system `/usr/bin/sandbox-exec`: a regular,
non-symlink, root-owned file with execute bits, no group/world write bits, and
read/execute access. It does not invoke the Seatbelt capability probe. Host
support and backend-file availability are separate checks; a present backend on
an unsupported macOS version does not make the command succeed. On non-macOS
hosts, or when host metadata cannot be read, backend availability is unchecked.

`profile validate NAME` first uses the existing read-only inspection codec and
safe store traversal to validate supported persisted structure. The v1/v2
persistence and [inspection output contract](profile-inspection.md) are unchanged.
It then resolves only the selected Skill references through the existing Devin
discovery rules: immediate child directories with regular `SKILL.md` files under
the selected global sources. Unselected roots are not enumerated; malformed
unselected entries do not become requirements. Empty selections pass without
source access. References use exact source-plus-relative-path identity: removed,
ambiguous, nested, or differently spelled references are not silently rebound.
Symlink handling follows existing discovery. Manifest contents and complete
bundle contents are not validated; a regular `SKILL.md` is the discovery rule.
No launch plan is constructed. Restore selected bundles or create a new Profile
selection when references no longer resolve.

Both commands are strictly passive. They do not start any subprocess (including
`--version`), query credentials, infer authentication from an identity name,
log in, allocate/recover Sessions, acquire locks, change permissions, migrate,
or write persistence. Version compatibility, authentication, and actual runtime
enforcement always remain unchecked. Validation also leaves platform, backend,
and executable checks unchecked. Passive success is not proof of launch
readiness; normal runtime and dry-run readiness behavior is unchanged.

Command words come first. `profile validate` accepts exactly one NAME before or
after `--json`. Each flag occurs at most once. Unknown/duplicate flags, extra
operands, `=`, `--`, pass-through, backend selection, bypass, and active options
are rejected. Use `acs help doctor`, `acs doctor --help`, or
`acs profile validate --help`. Help exits 0 on stdout; invalid syntax exits 1
with contextual stderr usage and no diagnostics JSON.

## Diagnostic JSON format 1

Each syntactically valid `--json` invocation writes exactly one compact JSON
object plus newline on stdout, with no stderr prose or color. The deterministic
format is separate from persisted schemas and the published inspection envelope.
It contains exactly:

- `formatVersion`: integer `1`.
- `operation`: `doctor` or `profile.validate`.
- `target`: `""` when no doctor target was selected, otherwise `devin`, `sandbox`,
  or `codex-auth`; always `""` for Profile validation.
- `checks`: an array in the following fixed order. Every check has exactly the
  string fields `id`, `status`, `code`, and `nextStep`.

| Check ID | Doctor | Profile validation |
| --- | --- | --- |
| `profile.structure` | unchecked | supported stored structure |
| `profile.sources` | unchecked | selected source resolution after valid structure |
| `host.platform` | native metadata and supported-platform policy | unchecked |
| `backend.file` | trusted system backend-file availability on macOS | unchecked |
| `executable.availability` | selected target only; otherwise unchecked | unchecked |
| `executable.version` | unchecked | unchecked |
| `authentication` | unchecked | unchecked |
| `runtime.enforcement` | unchecked | unchecked |

`status` is `pass`, `fail`, or `unchecked`. Exit 0 means every requested passive
check passed. Any requested failure or fatal prerequisite gives exit 1.
Unchecked facts neither count as passed nor independently fail the command.
A structure failure leaves source resolution unchecked (`structure_required`).

Stable codes are:

| Codes | Meaning |
| --- | --- |
| `not_requested` | Check outside the requested scope. |
| `not_probed`, `not_queried` | Active version/enforcement or authentication check deliberately not performed. |
| `supported_platform`, `unsupported_platform`, `platform_unavailable` | Supported metadata, unsupported host, or unreadable native metadata. |
| `backend_available`, `backend_unavailable`, `no_supported_backend` | Trusted backend available, unavailable/unsafe/inaccessible, or unchecked on this host. |
| `executable_available`, `executable_unavailable` | Requested executable found, or absent/unsafe/inaccessible. |
| `valid_structure` | Supported persisted Profile structure. |
| `structure_required` | Sources unchecked because structure could not be validated. |
| `selected_sources_resolved`, `selected_sources_unresolved`, `sources_unavailable` | Exact selected references resolved, missing/ambiguous, or selected root cannot be enumerated. |
| Inspection failure codes | `storage_unavailable`, `invalid_name`, `missing`, `unreadable`, `non_regular`, `too_large`, `invalid_structure`, `identity_mismatch`, `unsupported_content`; meanings match inspection. |

`nextStep` is fixed sanitized guidance, not a machine identifier; branch on
`id`, `status`, and `code`. Results contain no raw file contents, credentials,
environment values, Session data, generated policy, names/references from
unrelated sources, or private absolute paths. Human output reports the same
checks and guidance. Reads are observations, not a transactional snapshot;
concurrent changes can invalidate a later launch.

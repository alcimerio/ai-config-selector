# Common Profile format, migration, grants and projection

[Documentation index](../README.md)

New Profiles use envelope version 3. Version 1 and 2
remain readable and are never changed by inspection or launch.

Noninteractive authoring accepts only this supported v3 representation; see
[declarative creation](../guides/profiles.md#declarative-creation). Legacy documents continue
to use the established read, edit and explicit migration paths.

```json
{
  "version": 3,
  "name": "backend-review",
  "common": {
    "skills": {
      "version": 1,
      "selection": [
        {"source": "shared-agents", "relativePath": "backend-review"}
      ]
    },
    "instructions": {
      "version": 1,
      "selection": [
        {"source": "acs-instructions", "relativePath": "reviews/backend.md"}
      ]
    },
    "workspace": {
      "version": 1,
      "selection": {"access": "read-only"}
    },
    "paths": {
      "version": 1,
      "selection": {"entries": []}
    },
    "executables": {
      "version": 1,
      "selection": {
        "entries": [
          {"id": "git", "reference": {"kind": "fixed-search-name", "name": "git"}},
          {"id": "project-tool", "reference": {"kind": "workspace-relative", "path": "bin/tool"}}
        ]
      }
    },
    "environment": {
      "version": 1,
      "selection": {
        "entries": [
          {
            "id": "mode",
            "destination": "BUILD_MODE",
            "scope": "attached-process-tree",
            "source": {"kind": "host-environment", "name": "ACS_BUILD_MODE"},
            "required": false,
            "classification": "non-secret"
          },
          {
            "id": "token",
            "destination": "SERVICE_TOKEN",
            "scope": "attached-process-tree",
            "source": {
              "kind": "secret-reference",
              "provider": "host-environment",
              "reference": "ACS_SERVICE_TOKEN"
            },
            "required": true,
            "classification": "secret"
          }
        ]
      }
    }
  },
  "overlays": {
    "devin": {"version": 1},
    "codex": {"version": 1, "authRef": "work"}
  }
}
```

The envelope, each common capability, and each target overlay are independently
versioned. Skills and instructions retain exact `source` plus `relativePath` identity; a missing
or differently spelled source entry is not rebound by display name or cleaned
path. Unknown common capabilities and unsupported selected overlays fail
closed. Unknown inactive overlays can be reported by passive inspection but do
not grant authority. Because rewriting their representation could lose unknown
data, edit, clone and rename refuse them before preview.

## Workspace authority

New v3 Profiles default to a read-only workspace and a private writable
Session. In the Profile Builder, Workspace offers an explicit `Read and write
(coding work)` choice. The resolved common intent is passed unchanged to native
sandbox checks and every probe or attached process. Seatbelt omits workspace
write rules for read-only Profiles. Session writes remain allowed in both modes.

Legacy v1/v2 Profiles retain writable-workspace authority and their established
synthetic-home paths. An approved legacy edit/clone/rename produces canonical
v2, preserving that authority and placement. It does not silently adopt v3.

## Instruction bundles

`common.instructions` version 1 selects regular UTF-8 Markdown files under
`~/.acs/instructions`, including nested paths, through the builder's
**Instructions** category. Selection is explicit, never every file by default.
Profiles store only `{source, relativePath}` references with source
`acs-instructions`; host text is not stored in the Profile. The canonical
reference array may be empty (`[]`). Omission remains valid for older Profiles;
unknown present versions and malformed selections fail strict admission.

### Source limits and capture

Select at most 64 files, 128 KiB each and 1 MiB total. Relative paths have at
most 16 components and 1,024 UTF-8 bytes. Source directories/files must be owned
by the effective user and not group/world writable. Symlinks, nonregular,
empty or BOM-prefixed files, invalid UTF-8, NUL and terminal controls are refused.
Tabs, LF, CRLF and the absence of a final newline are preserved.

Before Session allocation, ACS traverses no-follow directory descriptors,
reads bounded bytes from each validated file descriptor, and checks identity
and metadata around capture. Those immutable bytes are materialized at
`$SESSION_HOME/.acs/common/v1/instructions/<source>/<relativePath>` without
reopening host sources. Generic `acs run` can consume them without Devin paths.
Codex receives common material only; ACS does not project it into Codex
instruction configuration or claim automatic activation.

### Devin projection and ambient configuration

Devin also receives one rule per selected file under synthetic-home
`.devin/rules`. Names are `acs-instruction-` plus the full lowercase SHA-256 of
`source + NUL + relativePath`, followed by `.md`. Fixed frontmatter
`---\ntrigger: always_on\n---\n` precedes the exact bytes; source frontmatter is
body text and cannot change activation. Before authentication, contained Devin
must list each selected name exactly once as always-on and show its projected
path, exact provider, activation and expected rendered body. The renderer trims
outer whitespace and adds a display newline; ACS separately verifies exact
prefixed bytes on disk.

Workspace rules and AGENTS files remain ambient Devin configuration. ACS neither
copies them into Profiles nor rewrites the workspace, and selected rules are
not necessarily the only discoverable rules. A pinned local observation found
that a `.git` marker changes AGENTS' workspace root; non-Git workspaces can show
additional rows that must not automatically be classified as workspace
inheritance. The selected-rule check does not exhaustively enumerate or classify
ambient rules and does not prove model obedience.

An absent instruction root yields an empty catalog and missing saved selections;
a discovery error leaves selections unavailable and retained for repair. These
labels do not establish the origin of arbitrary AGENTS rows.
[Exchange](../guides/portable-profile-exchange.md) represents instruction sources as required
symbolic bindings, without host paths or bodies; import must bind
`acs-instructions` locally.

## Explicit filesystem paths

`common.paths` version 1 grants existing regular files or directories in
addition to the workspace. Entries have a stable lowercase ID, `read-only` or
`read-write` access, `file` or `directory` type, and either a portable
`workspace-relative` reference or a machine-local `local-absolute` reference.
Local absolute roots are limited to descendants of the real user home or a
mounted `/Volumes/<name>` filesystem; filesystem roots and broad system roots
are not grantable.

A directory grant covers descendants. An exact writable file permits in-place
writes only, requires a single-link regular file, and does not authorize parent
rename, replacement, or sibling creation. Grant the containing directory when
the target requires atomic replacement. ACS rejects missing or special files,
wrong types, escapes, unsafe symlinks, protected Profile/Session/authentication
state, writable target/runtime inputs, and observed identity changes. The same
captured grants are revalidated before Session creation and before every target
process preparation.

Seatbelt enforcement is pathname based. ACS detects identity and symlink drift
at its validation seams, but cannot exclude a cooperating external same-user
process replacing a pathname after the final check. Directory authority also
covers every name and hard link reachable inside that directory. These are
explicit proof limits, not stable-object enforcement claims.

Older v3 Profiles without `paths` remain readable as an empty compatibility
default without rewrite. New creation and confirmed mutation emit an explicit
empty or populated `paths` selection. A legacy edit that selects a nonempty
path grant is refused until the user performs explicit v3 migration.

## Executable visibility

`common.executables` version 1 makes selected existing regular executable files
readable to contained processes. Entries have a stable lowercase ID and one of
three references: `fixed-search-name` searches only
`/usr/local/bin:/usr/bin:/bin`; `workspace-relative` is anchored to the captured
workspace identity; and `local-absolute` is a private binding under the user
home, a mounted `/Volumes/<name>` filesystem, or ACS's fixed executable roots
`/usr/local/bin`, `/usr/bin`, and `/bin`. This fixed-root exception applies only
to executable visibility and does not broaden ordinary data-path grants.
The supported-root rule applies to the supplied logical local path. An accepted
logical symlink may resolve to a package-manager target outside that anchor;
ACS binds, protects, grants, and repeatedly revalidates the canonical target as
well as the captured logical chain. ACS never consults inherited `PATH` for a
fixed-search selection. It validates the logical chain, opens the canonical file without
following another final symlink, records identity and a content digest from the
same descriptor, and
revalidates the original search choice, logical symlink chain, workspace anchor,
identity, executable mode, and bytes at Check and every process Prepare.

Visibility does not select or invoke a command and is deliberately
non-exclusive: the native runtime already exposes bounded system files and
permits process execution. A workspace-relative executable covered by workspace
read remains requested intent but adds no redundant effective filesystem grant.
Scripts may need separate visibility for non-intrinsic interpreter symlinks or
runtime files; ACS never derives those grants from a shebang or command body.
Because process execution is deliberately non-exclusive, a directly addressed
Mach-O program that the native loader can start may still run without a
standalone executable-read fact. This category controls added pathname
visibility, not execution admission.
Logical symlinks such as a Homebrew-style `bin/tool` are supported, with exact
read access to both the validated logical link and canonical file and
metadata-only access to their captured ancestors. Executable selection itself
adds no write authority; an existing writable workspace or `common.paths` grant
may still authorize edits to a selected tool it already covers. The pathname
race after the final validation fence remains the
same explicit Seatbelt limit described for path grants.

Older v3 Profiles without `executables` read as an empty compatibility default.
New creation and confirmed mutation emit the explicit selection; legacy Profiles
must migrate before selecting a nonempty executable entry.

## Scoped environment

`common.environment` version 1 maps explicit host sources to new names in the
final attached process tree. Each entry has a stable lowercase ID, an uppercase
`destination`, the only supported scope `attached-process-tree`, a required
flag, and a classification. A `non-secret` entry uses an exact
`host-environment` source name and may be optional. A `secret` entry uses a
`secret-reference` with the current `host-environment` provider and is always
required. The host name or reference is a local lookup key, not a stored value.
Present empty values are preserved; an absent optional non-secret source is
omitted, while an absent required source fails before Session creation.

Destinations and source names use the bounded uppercase environment-name
grammar. ACS rejects duplicates, NUL bytes, oversized values and totals, and
destinations that could replace its runtime controls, including `HOME`, `PATH`,
XDG paths, locale/terminal controls, shell startup hooks, and `ACS_`, `DYLD_`,
`LD_`, or `LC_` prefixes. Values are freshly resolved for every execution; they
are excluded from Profiles, authority digests, explanations, exchange/history,
Session metadata, generated policies, argv, status probes, and diagnostics.
Passive inspection, validation, explanation, export, history, and restore
preview never read the provider.

On macOS, ACS transfers selected values over its private bounded supervisor
control channel after policy validation and immediately before final target
start. Values therefore transit trusted supervisor memory and then remain in
the target process environment for its normal lifetime; the target and its
descendants can intentionally read or print them. Devin Skills/authentication
preflights and Codex version/authentication/status probes do not receive them.
For a Codex launch with selected environment values, ACS disables Codex shell
snapshots because that target feature serializes exported process variables;
the selected values remain available to the real tool process and descendants.
Cleanup retains the private resource lease until descendant settlement is
proved; uncertain cleanup remains quarantined rather than claiming erasure.
Selected environment transport requires the supported macOS runtime. Unsupported
hosts fail closed before Session creation.

Older v3 Profiles without `environment` read as an empty compatibility default.
New creation and confirmed mutation emit the explicit selection. Only
host-environment references are supported; they are not durable credential
storage.

## Reference-only MCP servers

`common.mcp` version 1 selects local stdio servers by references to the
`common.executables`, `common.paths`, and `common.environment` selections.
Arguments are ordered path or non-secret environment references; secret
environment entries may be delivered to the attached process tree but cannot
be used as argv items. See the [MCP Profile contract](../guides/mcp-profiles.md) for the
full schema, target projection, remote transport boundary, public lifecycle,
and current evidence limitations.

## Common material and projections

For v3, selected Skills are copied first to:

```text
$SESSION_HOME/.acs/common/v1/skills/<source>/<relativePath>/
```

Selected instruction files use the separate common location and target behavior
described under [instruction bundles](#instruction-bundles).

The source segment prevents two source identities from being flattened. ACS
rejects normalized duplicates, parent/child overlaps, and native case aliases
before sandbox execution. Bundle file modes and internal relative symlinks are
preserved.

`acs sandbox` selects no target overlay and exposes only the common copy. `acs
devin` and `acs codex` require their exact supported overlay and project from
the already materialized common copy into the target's per-source managed
roots. Codex uses `$SESSION_HOME/.codex/skills/<source>/<relativePath>`. The
projection does not reread the original host bundle. A supported inactive
overlay is preserved by mutation; an unknown inactive overlay remains inert,
but rewrite commands refuse it when lossless preservation cannot be proven.

Whole-workspace read includes project-local files. “Selected only” describes
ACS-managed global materials: it does not claim to hide project-local Skills or
files inside the explicitly granted workspace or writable Session.

## Explicit migration and outcomes

Run `acs profile migrate NAME`. The same Profile Builder used for mutations
shows an immutable preview with changed schema fields, retained defaults,
effective workspace authority, common paths, Devin projection paths and exact
resulting bytes. The migration uses the existing byte-oriented, revision-bound
repository Replace transaction; it adds no lock, journal or persistence engine.

The default migration preserves legacy workspace write explicitly. A later
editor change to read-only is a separately visible authority reduction.
Cancellation, refusal, revision conflict and other `NotCommitted` outcomes
leave prior bytes unchanged. Once a decision may exist, ACS continues to report
`Committed` or `Unknown` and any recovery requirement truthfully. Recovery can
roll publication forward and is not a universal rollback or backup feature.

`profile list`, `profile show` and `profile validate` are passive. They do not
migrate, canonicalize, discover inactive overlays, inspect target readiness,
access authentication, allocate a Session or write files. Structural support,
selected source availability, overlay execution support and native enforcement
are separate observations. See the [shared Devin/Codex behavior and evidence
guide](shared-target-conformance.md) for the maintained cross-target contract
and evidence limits.

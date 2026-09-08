# Common Profile format, migration, grants and projection

Development source writes new Profiles as envelope version 3. Version 1 and 2
remain readable and are never changed by inspection or launch.

Noninteractive authoring accepts only this supported v3 representation; see
[Declarative Profile creation](profile-creation.md). Legacy documents continue
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
    }
  },
  "overlays": {
    "devin": {"version": 1},
    "codex": {"version": 1, "authRef": "work"}
  }
}
```

The envelope, each common capability, and each target overlay are independently
versioned. Skills retain exact `source` plus `relativePath` identity; a missing
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
write rules for read-only Profiles; the retained Linux compiler uses a read-only
workspace bind. Session writes remain allowed in both modes.

Legacy v1/v2 Profiles retain writable-workspace authority and their established
synthetic-home paths. An approved legacy edit/clone/rename produces canonical
v2, preserving that authority and placement. It does not silently adopt v3.

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

## Common material and projections

For v3, selected Skills are copied first to:

```text
$SESSION_HOME/.acs/common/v1/skills/<source>/<relativePath>/
```

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
guide](shared-target-conformance.md) for the maintained cross-target contract,
native fixture boundary and pending real-use checklist.

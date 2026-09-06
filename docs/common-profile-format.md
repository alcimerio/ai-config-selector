# Common Profile format, migration, grants and projection

Development source writes new Profiles as envelope version 3. Version 1 and 2
remain readable and are never changed by inspection or launch.

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
are separate observations.

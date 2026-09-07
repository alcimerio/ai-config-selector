# Exchange portable Profile intent

Development source supports a separately versioned, sanitized Profile exchange
format. Local Profile JSON is machine persistence and is not an export format.
Exchange documents contain only supported version-3 stored intent and explicit
symbolic requirements; they never contain resolved host paths, Skill assets,
credentials, tokens, OAuth state, Sessions, repository metadata, generated plans,
or target state.

```sh
acs profile export backend-review
acs profile export backend-review --file backend-review.acs-profile.json
acs profile import validate --file backend-review.acs-profile.json --json
acs profile import validate --file backend-review.acs-profile.json --bindings local-bindings.json
acs profile import --file backend-review.acs-profile.json --as imported-review --bindings local-bindings.json --dry-run
acs profile import --file backend-review.acs-profile.json --as imported-review --bindings local-bindings.json
```

Existing `acs profile validate NAME` still validates one stored Profile. Import
validation is the distinct `acs profile import validate` command. Input is an
explicit local regular file; stdin and remote URLs are not supported.

## Export format and output

Exchange version 1 supports common Skills v1, workspace v1, and exact maintained
Devin v1 and Codex v1 overlays. A version-1 or version-2 local Profile must first
use the existing explicit `acs profile migrate NAME` workflow. Export never
migrates or rewrites its source.

Without `--file`, stdout is only deterministic indented JSON plus its final
newline. The sanitized classification report is stderr, so ordinary redirection
captures clean machine-readable JSON. With `--file`, stdout is empty. File output
uses a mode-0600 same-directory temporary, complete write and sync, exclusive
no-replace publication, and directory sync. Existing files, including symlinks,
are never replaced. A failure after publication says that the destination may
already contain the complete export and must be inspected before retrying.
Cancellation is observed inside the publication action immediately before the
exclusive rename. That observation and the filesystem syscall are not one atomic
operation: if rename succeeds, the outcome remains published even when
cancellation arrives concurrently or afterward, and directory durability is
still attempted before cancellation and durability errors are reported together.

Local source names and a nonempty Codex `authRef` are replaced by deterministic
symbols. Skill paths remain exact source-relative logical intent; they are not
project-relative paths and are never rebound by display name. For example:

```json
{
  "exchangeVersion": 1,
  "profile": {
    "common": {
      "skills": {
        "version": 1,
        "selection": [
          {"sourceBinding": "source-1", "relativePath": "backend-review"}
        ]
      },
      "workspace": {
        "version": 1,
        "selection": {"access": "read-only"}
      }
    },
    "overlays": {
      "codex": {"version": 1, "authBinding": "authentication-1"},
      "devin": {"version": 1}
    }
  },
  "requirements": {
    "sources": [{"id": "source-1"}],
    "authentications": [
      {"id": "authentication-1", "kind": "codex-chatgpt"}
    ]
  }
}
```

Unknown fields, future versions, unknown or inactive overlays, unsupported
capabilities, embedded assets, and unclassified content refuse the whole export.
ACS never silently removes them.

## Explicit local bindings

Import uses a separate local binding document:

```json
{
  "bindingVersion": 1,
  "sources": {"source-1": "shared-agents"},
  "authentications": {"authentication-1": "work"}
}
```

Each requirement needs exactly one mapping and unused mappings are rejected.
Source values are exact registered identities (`devin-config` or
`shared-agents`), not display names. Authentication values are only canonical
opaque ACS identity names; validation never queries Keychain or reads credential
values. Duplicate, case/Unicode-normalized alias, and parent/child Skill
destinations are rejected both before and after binding. Two symbols mapped to
one local source therefore cannot evade collision checks, while the same relative
name under two distinct sources remains correctly namespaced.

Complete bindings mean only that every symbolic requirement has a valid local
mapping. Source availability, named-auth existence/status, target executables,
sandbox enforcement, and runtime readiness remain explicitly unchecked. Missing
Skill material or authentication can still make a later launch fail. Unresolved
or unsupported input is never persisted in the runnable Profile namespace.

## Bounded validation and publication

Exchange and binding files are each limited to 1 MiB and read once after their
opened descriptor is verified as regular and nonblocking. A symlink to a regular
file is supported and path replacement after open does not redirect the read;
the captured bytes begin the immutable candidate guarantee. ACS does not claim a
descriptor prevents concurrent in-place writes. FIFO, device, socket, directory,
oversize, truncated, invalid UTF-8, unpaired surrogate, duplicate-key, trailing,
over-deep, over-count, unsafe-path, and unsupported-schema input fails before
publication. No hook, subprocess, discovery, provider, Session, network access,
or recovery runs during validation.

The lexical preflight permits at most 64 container levels, 65,536 tokens, 256
members per object, 4,096 array elements, and 4,096 decoded UTF-8 bytes per
string. Each binding class permits 64 entries; Skills permit 4,096 entries; a
Skill path permits 1,024 UTF-8 bytes and 128 components. Binding IDs and local
Profile/auth names have their documented bounded ASCII grammars.

Human and JSON diagnostics distinguish structure, semantics, `bindings:
complete` or `unresolved`, and destination status from unchecked source
availability/authentication/runtime. JSON format 1 contains exactly
`formatVersion`, `operation`, `status`, `code`, `structure`, `semantics`,
`bindings`, `destination`, `sourceAvailability`, `authentication`, `runtime`,
`requiredSources`, and `requiredAuthentication`. Exit 0 is fully valid
with complete bindings, exit 2 is supported intent with unresolved bindings, and
exit 1 is invalid, unsafe, unsupported, or unreadable input.

`--dry-run` also validates the explicit `--as NAME`, passively checks the
destination is absent, and prints the exact canonical local v3 candidate. It
creates no Profile directory, lock, journal, Session, credential, or other state.
Actual import uses the existing revisioned conditional Create transaction. It
never replaces a destination or case alias. Transaction messages preserve
`not committed`, `committed`, `unknown`, and recovery-required precedence; a
reporting error after commit never claims that publication did not occur.

The exchange does not carry Skill contents or authentication, provide a backup,
verify readiness, convert targets, synchronize remotely, or provide signatures,
encryption, history, downgrade, overwrite, or automatic updates. Supported
runtime remains macOS 26 on Apple Silicon; local Linux tests are supplementary.

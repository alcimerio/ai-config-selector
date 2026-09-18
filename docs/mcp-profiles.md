# MCP server selections in Profiles

Development-source version-3 Profiles may select local MCP servers under
`common.mcp`. The category has version 1 and a `selection.servers` array. ACS
stores references to already selected executables, filesystem paths, and
environment entries; it does not store command text, arbitrary argument
values, endpoint URLs, headers, or resolved environment values.

```json
{
  "version": 3,
  "name": "review-with-local-tools",
  "common": {
    "skills": {"version": 1, "selection": []},
    "workspace": {"version": 1, "selection": {"access": "read-write"}},
    "executables": {
      "version": 1,
      "selection": {
        "entries": [
          {"id": "review-server", "reference": {"kind": "workspace-relative", "path": "tools/review-mcp"}}
        ]
      }
    },
    "paths": {
      "version": 1,
      "selection": {
        "entries": [
          {"id": "review-input", "access": "read-only", "type": "file", "reference": {"kind": "workspace-relative", "path": "policy/review.json"}}
        ]
      }
    },
    "environment": {
      "version": 1,
      "selection": {
        "entries": [
          {
            "id": "review-flag",
            "destination": "PROFILE_REVIEW_FLAG",
            "scope": "attached-process-tree",
            "source": {"kind": "host-environment", "name": "ACS_REVIEW_FLAG"},
            "required": true,
            "classification": "non-secret"
          },
          {
            "id": "review-mode",
            "destination": "PROFILE_REVIEW_MODE",
            "scope": "attached-process-tree",
            "source": {"kind": "host-environment", "name": "ACS_REVIEW_MODE"},
            "required": true,
            "classification": "non-secret"
          },
          {
            "id": "review-token",
            "destination": "PROFILE_REVIEW_TOKEN",
            "scope": "attached-process-tree",
            "source": {"kind": "secret-reference", "provider": "host-environment", "reference": "ACS_REVIEW_TOKEN"},
            "required": true,
            "classification": "secret"
          }
        ]
      }
    },
    "mcp": {
      "version": 1,
      "selection": {
        "servers": [
          {
            "id": "review",
            "transport": "stdio",
            "executableRef": "review-server",
            "arguments": [
              {"kind": "environment", "ref": "review-flag"},
              {"kind": "environment", "ref": "review-mode"},
              {"kind": "path", "ref": "review-input"}
            ],
            "inputRefs": ["review-input"],
            "environmentRefs": ["review-flag", "review-mode", "review-token"],
            "disabledTools": ["remove_policy"]
          }
        ]
      }
    }
  },
  "overlays": {"devin": {"version": 1}}
}
```

Each server ID is unique, 1–64 lowercase ASCII characters, starts with a letter,
and contains only letters, digits, `.`, `_`, or `-`. At most 64 servers are
accepted. `transport` currently accepts only `stdio`. `executableRef` must
identify a selected executable grant. `arguments` is an ordered list of up to
128 typed references: `path` arguments must also appear in `inputRefs`, and
`environment` arguments must refer to selected non-secret entries also named
in `environmentRefs`. Secret entries may appear in `environmentRefs`, but
never in `arguments`. A practical invocation such as
`review-mcp --mode "review with citations" policy.json` can use two
non-secret environment references for `--mode` and its value, followed by the
path reference. For example, set `ACS_REVIEW_FLAG=--mode` and
`ACS_REVIEW_MODE='review with citations'` before running
`acs devin --profile review-with-local-tools`; ACS resolves those values into
separate argv items at launch, preserving spaces without persisting either
value. Path arguments resolve from the same validated filesystem grants as
other Profile paths. Up to 64 `inputRefs` declare the selected path IDs eligible
for path arguments; listing an input does not add an argv item by itself.

`environmentRefs` may contain up to 128 selected entries. `disabledTools` is
an optional sorted set of up to 256 ASCII target tool names (maximum 128
characters each; letters, digits, `.`, `_`, `:`, `/`, and `-`, starting with a
letter or digit). If supplied, it must be an array; `null` is rejected. The
complete selection is limited to 4,096 aggregate list items and 1 MiB. The
adapters project disabled names using the target's configuration field, but
filtering is a target feature rather than an ACS
containment boundary. Native proof of filtering and server invocation is still
required before this development feature is accepted. Unknown keys, duplicate
or aliased JSON keys, malformed references, null required lists, unsupported
transports, secret argv references, and unbound IDs reject the whole selection
rather than being discarded.

At launch, ACS compiles the selected server into a bounded Session recipe and
projects the local stdio command into Devin or Codex configuration. ACS's
launcher revalidates the selected executable and path identities, resolves the
typed argv references using the already selected child environment and execs
the server in place. The recipe contains references and identities, not
resolved environment values. Secret values remain available in the attached
process tree, however: ACS does not isolate environment variables per MCP
server. The target and its server processes can read selected values and their
descendants inherit that environment.

In this delivery remote MCP is unsupported. Profiles with URL, HTTP, SSE,
header or OAuth transport settings are rejected; these fields are not accepted
as inert placeholders. The selected executable visibility category remains
non-exclusive, and normal outbound-network authority still applies to a stdio
server. MCP selection does not create destination-specific network filtering.

Codex's generated MCP table is composed with the target's existing isolated
HOME and untrusted-project configuration; an empty table does not erase other
loaded entries. Devin's dedicated selected HOME config is combined with its
project/local config read restriction and import switches below. These
configuration probes inform composition but do not replace native public ACS
tests for actual target discovery, invocation, filtering, and cleanup.

## Authoring and lifecycle

`acs profile create --file` accepts the strict `common.mcp` category. The
interactive Profile Builder supports adding, editing, and removing one server
descriptor at a time. Both paths validate cross-category executable, input and
environment references before saving. Removing or renaming a referenced
capability is refused before Profile bytes or revision change. Generic
`acs run` preserves MCP intent and explains its applicability, but it does not
start a server or write target-native MCP configuration.

`acs explain devin|codex --profile NAME` reports the selected reference-only
MCP intent and target projection applicability. Requested facts describe what
the Profile selects; the target-added fact names the registered projection
the selected recipe would compile. It does not report MCP as effective runtime
enforcement or prove that a target started a server or applied tool filtering.
Explanation does not resolve environment values or start a target.

Portable Profile exchange includes MCP references and ordered argv without
embedding local filesystem values or environment values. Local executable,
path, and secret environment references use the existing explicit exchange
bindings; secret references are represented by symbols. Import validates all
references before conditional Profile creation. History and restore use the
existing Profile revision and local-binding rules; restore does not replay old
resolved paths or secret values. See the [common Profile format](common-profile-format.md),
[Profile creation](profile-creation.md), [portable exchange](portable-profile-exchange.md),
and [effective capability explanation](effective-capability-explanation.md).

## Devin import compatibility

To suppress documented ambient MCP imports, the Devin Session user config sets
`read_config_from.cursor`, `windsurf`, `claude`, `opencode`, and `zed` to
`false`, while leaving `agents_standard` and `copilot` unchanged. The pinned
CLI observation showed that a selected user `cursor: false` setting excludes
Cursor MCP configuration even when the project asks to enable it. The same
switches also suppress their documented non-MCP imports: Cursor rules;
Windsurf rules and Skills; and Claude rules, Skills and commands. OpenCode and
Zed switches cover their MCP imports. These compatibility effects also apply
when no MCP server is selected. Native Devin project rules and ACS-selected
Skills remain separate. Native target tests must continue to verify this
composition and ordinary Session writes; config-list output alone is not
runtime proof.

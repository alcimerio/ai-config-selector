# Plugins, hooks, and agent definitions: assessment

Status: assessment and test-only harness preparation. No extension schema,
target adapter, production execution path, or containment exception is added.

Base: `8afc0d0b060c524a29103d46c2f363d56330c6d3` (merged PR117).
Locked targets are Codex 0.149.1 (Darwin arm64) and Devin 3000.10.21. The
host-installed Codex 0.155.0 and current online documentation are separate
evidence and are not substituted for the locked targets. The Codex annotated
tag resolves to source commit `ff29a44391deccde0aba0f8390337d7f3c319ea4`;
the tag is unsigned. The locked Devin archive digest is
`c0b97f8197bf3ce895ff14aa19257c511154b49a0a195bba4962acb5e475c68e`.

The five Devin documentation members were byte-matched to that locked archive:

| Archive member | SHA-256 | Findings used |
| --- | --- | --- |
| `share/devin/docs/extensibility/plugins/overview.mdx` | `d5a237793675a7343a8094e93b6dd0e23049e4cb71eca1a8aced6dd4fbfd79e6` | Manifest precedence, components, local links, governance, fail-open hooks, persistent data. |
| `share/devin/docs/extensibility/plugins/quickstart.mdx` | `6528f5ae613a8d7ea1c2b1bbc67145f7a0071502530d72adc508cacd5cf7f623` | Local installation/authentication and update considerations. |
| `share/devin/docs/extensibility/hooks/overview.mdx` | `39ee1cf1425161bbab7890d7f23480547429582002a9a1aad50b32ff54692276` | Hook discovery, event input/output, matchers, SessionStart and exit semantics. |
| `share/devin/docs/extensibility/hooks/lifecycle-hooks.mdx` | `970cb20b3ab8e9a7c50c6455db94e613c4b0cd6cbfc74de39eecc0cc3ec3bc29` | Lifecycle ordering, SessionEnd intent, stop/block behavior and cleanup limits. |
| `share/devin/docs/subagents.mdx` | `8bdeec164c82585ba45c2507e634660fc1c2ea56b698c2956f034d3bf0a921fa` | Agent fields, default-all tools, approvals, nesting and parked interruption. |

The Codex source links below refer to commit
`ff29a44391deccde0aba0f8390337d7f3c319ea4`; its annotated tag is unsigned.

## Decision matrix

| Concept / target | Pinned contract and discovery | Authority and lifecycle | Decision and prerequisites |
| --- | --- | --- | --- |
| Codex plugin | Root `plugin.json` and OpenAI overlay precedence are target-owned; package capabilities include Skills, MCP and hooks. | Plugin hooks use target trust; plugin root/data and installed lifecycle are additional authority. ACS currently disables Codex plugins. | Consider only an identity-pinned local package overlay. Exclude marketplace, dependencies, remote auth, updates and persistent data until native discovery, trust and cleanup are proven. |
| Devin plugin | Manifest precedence is `.devin-plugin`, `.claude-plugin`, then root; local installs are live-linked. Governance and managed manifests have fail-open cases. | Plugins may add rules, MCP, hooks, agents and persistent `PLUGIN_DATA`; this is not equivalent to a disposable Session. | Consider only explicit local activation with common grants for selected resources. Defer Cloud sync, credentials, dependencies, updates, governance and persistent data. |
| Codex hook | Pinned source defines layered discovery, normalized-definition trust hashes, command/MCP handlers, SessionStart and other lifecycle events. Normal command completion can leave detached helpers. | Common grants can cover selected executable/input/MCP references; trust, shell ABI, event timing and output decisions remain target-owned. | A compiler prototype records selected resources without activating the definition. Installed discovery remains unobserved; async/background support remains deferred until settlement is proven. |
| Devin hook | Pinned docs define project `hooks.v1.json`, event JSON, command output/decisions, SessionStart before the first prompt, and incomplete cross-source merge details. Exit semantics distinguish success, block and logged errors. | Hook fail-open/timeout/child semantics are target behavior, not ACS enforcement. | The current opt-in harness assesses one bounded project SessionStart witness through public ACS composition. No hook schema is shipped. |
| Codex role/agent | Pinned role application is a typed allowlist of model/prompt/personality/service-tier and feature/Skill controls. It preserves parent authority. | Roles do not add arbitrary filesystem, environment, network, credential or sandbox authority; threads are not necessarily OS processes. | A narrow descriptive role overlay is a future candidate. Reject unsupported authority fields and defer model-assisted/native lifecycle claims. |
| Devin custom agent | Pinned Markdown agents support model, prompt, `allowed-tools` and `max-nesting`; default tool access is all, background agents inherit approvals, and parent interruption parks agents. | Target tool policy is not an OS grant; no independent per-agent filesystem/env/network/cleanup lease is documented. | Consider only a target-owned identity/prompt/tool overlay after bounded selection and lifecycle evidence. Keep parent ACS grants as the OS boundary. |

For every row, discovery/precedence, trust, executable and filesystem effects,
environment/secrets, network, project inheritance, failure precedence and
descendant cleanup remain separate questions. Compile-only or parser results do
not establish runtime containment.

## Field-level decisions

### Codex plugins

- Common existing intent: selected Skill, executable, path, environment, and
  reference-only MCP components can use existing typed grants.
- Target-owned overlay candidate: plugin identity, root `plugin.json`, inline
  `extensions.com.openai` precedence, package namespace, and target
  serialization.
- Defer: marketplace policy, remote installation/authentication, dependencies,
  updates, persistent plugin data, and plugin lifecycle cleanup. ACS currently
  disables Codex plugins, and the pinned loader's portable/inline precedence is
  not a common package contract.

### Devin plugins

- Common existing intent: selected package executables, inputs, environment
  references, and MCP leaves can reuse existing grants after explicit identity
  selection.
- Target-owned overlay candidate: `.devin-plugin`/`.claude-plugin`/root
  manifest precedence, plugin namespace, Skills/rules/MCP serialization, and
  local activation.
- Defer: live-linked source mutation handling, sign-in/Cloud sync, repository
  credentials, recursive dependencies, governance, `PLUGIN_DATA`, updates and
  uninstall/prune cleanup. The pinned docs explicitly distinguish these
  lifecycles from a disposable ACS Session and document fail-open cases.

### Codex hooks

- Common existing intent: selected command/MCP executable, input, path,
  environment and bounded output destinations can reuse typed grants.
- Target-owned overlay candidate: event/matcher, normalized-definition trust
  hash, shell/JSON serialization, timeout and decision/output semantics.
- Defer: prompt/agent hooks, async/background settlement, detached helper
  cleanup and executable-byte identity. Pinned command completion can permit a
  detached helper; the present native harness is Devin-only, so no Codex hook
  runtime evidence is claimed.

### Devin hooks

- Common existing intent: the prepared SessionStart witness uses selected
  executable/input references, protected/outside operation checks and the
  existing ACS Session/MCP lifecycle.
- Target-owned overlay candidate: project `hooks.v1.json`, event/matcher,
  command shell ABI, event JSON, timeout and hook decision/output handling.
- Defer: complete cross-source merge precedence, prompt hooks, exit-2 versus
  other-error policy beyond the documented table, detached-child cleanup and
  fail-open behavior as ACS enforcement. The first CI experiment failed with
  no valid hook receipt; invocation and physical grant effects remain unproven.

### Codex roles/agents

- Common existing intent: none for role identity or model/prompt state; parent
  ACS grants remain the OS authority boundary.
- Target-owned overlay candidate: role identity, instructions, model/reasoning/
  personality/service-tier overrides, and typed feature/Skill disables.
- Defer: arbitrary role filesystem/environment/network/credential/sandbox
  fields, nested OS leases, and child cleanup. Pinned
  [`role.rs`](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core/src/agent/role.rs#L35-L125)
  applies a typed allowlist while preserving parent authority; it does not
  widen authority.

### Devin custom agents

- Common existing intent: parent-selected executable/path/environment/MCP grants
  can remain the physical boundary; no agent-specific OS grant is inferred.
- Target-owned overlay candidate: agent identity, Markdown prompt/model,
  `allowed-tools`, and `max-nesting`.
- Defer: default-all tool selection, foreground/background approval inheritance,
  parked interruption, nested-agent settlement, and per-agent filesystem,
  environment, secret or network leases. The pinned docs describe these as
  target orchestration semantics, not ACS containment.

### Source-backed distinctions

The locked Codex plugin loader gives the root `plugin.json`/Agent Plugins
manifest precedence and applies marketplace policy before activation. Plugin
hooks receive target-provided root/data environment and installed packages have
their own lifecycle; ACS therefore does not treat package discovery or plugin
data as common grants. See the pinned
[manifest resolver](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core-plugins/src/agent_plugin_manifest.rs#L64-L195),
[marketplace policy](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core-plugins/src/marketplace_policy.rs#L210-L304),
and [plugin hook environment](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/hooks/src/engine/discovery.rs#L248-L267).

Codex hook trust hashes the normalized definition, not the referenced
executable bytes. Command hooks have shell/event/stdin/output semantics, and
normal completion can permit detached helpers; those facts require a separate
identity and settlement proof. See [hook discovery and trust](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/hooks/src/engine/discovery.rs#L120-L194),
[hashing](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/hooks/src/engine/discovery.rs#L650-L793),
and [command execution](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/hooks/src/engine/command_runner.rs#L195-L445).

Codex roles are narrower than target tool permissions: pinned
[`agent/role.rs`](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core/src/agent/role.rs#L35-L125)
applies typed model/prompt/personality/service-tier and feature/Skill controls
while preserving parent authority. Role discovery and config-file selection are
covered by [`agent_roles.rs`](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core/src/config/agent_roles.rs#L20-L111).
Neither source establishes arbitrary role filesystem, environment, network,
credential or sandbox authority. Devin custom agents have the opposite
documented default: `allowed-tools` defaults to all (subagents.mdx295-303),
background approvals inherit and parent interruption parks rather than kills
(subagents.mdx167-180). Neither target's role/agent behavior is an ACS OS
lease.

Pinned Devin documents describe `.devin-plugin/plugin.json`, local live-linked
installs, project/user/plugin precedence, `.devin/hooks.v1.json`, command-hook
event JSON, and `.devin/agents` Markdown definitions. In the verified
`extensibility/plugins/overview.mdx`, manifest precedence is at lines 79-101
and local installation/authentication at lines 136-153 and 185-193. In
`extensibility/hooks/overview.mdx`, the explicit exit table is lines 178-186
and hook discovery is lines 188-219. In `subagents.mdx`, interruption is lines
167-180 and agent frontmatter/tools are lines 295-303. The bundled members and
their hashes are listed above. Their contracts include plugin-hook fail-open
behavior, managed-manifest fetch failure dropping forbids, custom-agent
default-all tools, inherited background approvals, and parked parent
interruption. Missing complete cross-source merge algorithms and unspecified
child settlement remain evidence gaps; they are not filled by this assessment.

Current primary portable contracts are also documented in [OpenAI plugin
packaging](https://developers.openai.com/plugins/build/plugins), [Codex
hooks](https://learn.chatgpt.com/docs/hooks), and [Codex
subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
Those pages may describe newer behavior than the locked binaries and are not
runtime proof.

## Current ACS boundary and evidence

ACS production composition currently supports typed Skills, instructions,
workspace, paths, executables, environment references and reference-only MCP.
The assessment tests retain ordinary MCP reference-composition checks and add
representative plugin manifests, role files and hook definitions for both
targets. Both real registries run `ResolveFor`, `Plan`, filesystem/executable
grant resolution and `Materialize`. An explicitly extracted package Skill is
compared byte-for-byte at its common and target destinations; the complete
generated file inventory confirms that selected role/hook data does not become
an activated extension. Missing selected definitions and executables are
refused. [Fixture details and unrepresented fields](../internal/extensionassessment/testdata/README.md)
explain this assessment-only extraction boundary. These tests do not establish
vendor parser acceptance, installed discovery or runtime authority.

Current constraints remain explicit: Codex plugins are disabled in production
semantics/projections; MCP environment names select references but do not narrow
helper inheritance; outbound network authority is coarse; and there is no
independent per-agent filesystem, environment, secret, network or descendant
lease. Unknown or unsupported extension fields must fail closed rather than
disappear.

The native hook test is enabled only in the separate promoted-artifacts CI
step with explicit opt-in. The first promoted
run reached the assessment but failed before a valid hook receipt was
available; a fixed-code diagnostic sidecar now distinguishes invocation and
bounded witness stages without exposing event data or paths. No successful
native hook observation is claimed here.

## Native hook assessment status

The test-only Devin hook harness prepares a project `SessionStart` definition,
explicit hook executable reference, bounded event input, selected-input read,
protected-config/outside write-denial attempts, atomic exclusive receipt
publication, PID/PPID/session/executable/input evidence, and a first-input gate.
Existing MCP, public ACS, live-session, natural-exit and descendant checks remain
unchanged. The native glue now validates the receipt before successful
completion acknowledgement. The experiment is currently a failed native
observation, not a passing gate; independently reviewed source is not runtime
evidence. MCP evidence is not presented as hook-child cleanup evidence.

The planned invocation is deliberately separate from normal gates:

```text
ACS_RUN_NATIVE_DEVIN_HOOK_ASSESSMENT=1 \
  ACS_TEST_DEVIN_BINARY=<locked Devin member> \
  ACS_TEST_DEVIN_ARCHIVE=<locked archive> \
  ACS_PROMOTED_BINARY=<promoted ACS> \
  ACS_PROMOTED_VERSION=<version> \
  ACS_PROMOTED_SANDBOX_BACKEND=available \
  go test ./acceptance -run '^TestPromotedArtifactNativeDevinSessionStartHook$' -count=1 -v -timeout=12m
```

This command is the exact separate CI invocation; it is not part of the release
workflow or mandatory MCP gate. The step discovers the named test, sets the
explicit opt-in and locked target paths through environment values, and applies
a bounded Go timeout. Receipt PID/PPID fields are structural evidence; they do
not establish independent process ancestry, natural hook exit, or detached hook
cleanup. Native success would prove only this documented synchronous hook event
and its observed physical grant effects under the tested public ACS/MCP
composition; it would not establish common hook support, plugin support, or
general detached-child cleanup.

## Reusable tests and deferred work

Reusable now are typed reference validation, production authority composition,
canonical identity checks, Session-scoped grants and existing cleanup receipts.
Still requiring target-specific evidence are package discovery/precedence,
marketplace governance, hook trust and output semantics, agent inheritance,
plugin writable data, and target-owned installation state.

No private implementation drafts or local evidence paths are part of this
product-facing decision record. Follow-up modeling remains private until the
target contracts and native evidence above are independently accepted.

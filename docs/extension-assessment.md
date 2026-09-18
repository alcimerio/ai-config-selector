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
| Codex hook | Pinned source defines layered discovery, normalized-definition trust hashes, command/MCP handlers, SessionStart and other lifecycle events. Normal command completion can leave detached helpers. | Common grants can cover selected executable/input/MCP references; trust, shell ABI, event timing and output decisions remain target-owned. | A compiler prototype records selected resources without activating the definition. Installed untrusted metadata discovery and malformed-definition reporting passed with bounded optional startup metadata requests; async/background support remains deferred until settlement is proven. |
| Devin hook | Pinned docs define project `hooks.v1.json`, event JSON, command output/decisions, SessionStart before the first prompt, and incomplete cross-source merge details. Exit semantics distinguish success, block and logged errors. | Hook fail-open/timeout/child semantics are target behavior, not ACS enforcement. | The current opt-in harness assesses one bounded project SessionStart witness through public ACS composition. No hook schema is shipped. |
| Codex role/agent | Pinned role application is a typed allowlist of model/prompt/personality/service-tier and feature/Skill controls. It preserves parent authority. | Roles do not add arbitrary filesystem, environment, network, credential or sandbox authority; threads are not necessarily OS processes. | A narrow descriptive role overlay is a future candidate. Reject unsupported authority fields and defer model-assisted/native lifecycle claims. |
| Devin custom agent | Pinned Markdown agents support model, prompt, `allowed-tools` and `max-nesting`; default tool access is all, background agents inherit approvals, and parent interruption parks agents. | Target tool policy is not an OS grant; no independent per-agent filesystem/env/network/cleanup lease is documented. | Consider only a target-owned identity/prompt/tool overlay after bounded selection and lifecycle evidence. Keep parent ACS grants as the OS boundary. |

For every row, discovery/precedence, trust, executable and filesystem effects,
environment/secrets, network, project inheritance, failure precedence and
descendant cleanup remain separate questions. Compile-only or parser results do
not establish runtime containment.

## Installed-evidence ledger

Direct contained installed-target discovery and ACS compiler composition are
separate evidence classes. Discovering a target definition does not make it an
ACS Profile capability. The rows distinguish prepared cases from observed runs.

| Target / concept | Observable and negative case | Status and limit |
| --- | --- | --- |
| Codex plugin | `TestNativeInstalledExtensionDiscovery` adds a local marketplace, checks available and installed package identity, and checks missing-plugin refusal with unchanged inventory. | Passed (1.89 seconds). The plugin Session recorded zero HTTP requests. No plugin tool execution or runtime authority claim. |
| Devin plugin | `TestNativeInstalledExtensionDiscovery` installs a local package, checks its identity and Skill inventory, and checks malformed-package refusal with unchanged inventory. | Passed (1.68 seconds), including local inventory and malformed-package refusal under bounded synthetic startup replies. No real authentication, update or persistent-data lifecycle claim. |
| Codex hook | `TestNativeInstalledExtensionDiscovery` checks untrusted hook discovery metadata and normalized hash, absence of the execution tripwire, and malformed-definition reporting in fresh Sessions. | Passed (0.83 seconds). Positive and malformed Sessions each observed exactly one allowed metadata request, with fixed `metadata-count=1`, `forbidden=0`, and `overflow=0`; no hook execution or child lifecycle claim. |
| Devin hook | `TestPromotedArtifactNativeDevinSessionStartHook` observes a selected project hook, receipt, selected-input read, protected/outside write denials, and existing MCP/Session checks. | Three repetitions passed in 10.00, 10.00 and 9.36 seconds. Earlier failed runs remain recorded; the old logs cannot prove that every failure was a benign race. Receipt or diagnostic absence cannot prove non-invocation; MCP cleanup is not hook-child cleanup proof. |
| Codex role/agent | `TestNativeInstalledCustomCodexAgentDiscovery` checks the initial Responses request for the exact custom role catalog entry in selected and absent cases. | Selected and absent cases passed (25.43 seconds total); no child-agent invocation, custom-instruction execution, or independent agent authority claim. |
| Devin custom agent | `TestPromotedArtifactNativeCustomDevinAgentDiscovery` checks the initial request system catalog for the exact Markdown profile entry in selected and absent cases. | Selected and absent cases passed (18.84 seconds total); no child-agent invocation or child lifecycle claim. |

The latest observations are from commit
`8aca958410d26a7762106e760d945f2aa466d9c0` in the
[promoted artifact validation job](https://github.com/alcimerio/ai-config-selector/actions/runs/35369714139/job/105680652306).
The shared native gates, both plugin cases, both paired agent catalog cases,
Codex hook discovery, and three Devin hook repetitions passed. The Codex
plugin Session recorded zero HTTP requests. Each fresh Codex hook Session
recorded one exact optional metadata request, with forbidden and overflow
counters both zero. The Devin hook repetitions took 10.00, 10.00 and 9.36
seconds; whole-test durations are not hook latency measurements.

The allowed Codex startup request is source-backed, not an inferred model
request: pinned [`remote_legacy.rs:123-157`](https://github.com/openai/codex/blob/ff29a44391deccde0aba0f8390337d7f3c319ea4/codex-rs/core-plugins/src/remote_legacy.rs#L123-L157)
issues the optional authless `GET /plugins/featured?platform=codex` with an
empty body. The fixture returns the existing empty 501 response and provides
no successful inference or catalog response. Any other route, method, query, body,
credential header, duplicate, or overflow remains forbidden.

At `3baf0c6f661c2e6d36336c64ae836d9ed5ed0fde`, the
[preceding discovery job](https://github.com/alcimerio/ai-config-selector/actions/runs/35366014035/job/105668723178)
passed both plugin cases, both paired catalogs, and three Devin hook repetitions
(7.30, 7.00 and 7.10 seconds). Codex hook discovery failed only its aggregate
backend-request counter. That counter did not record the request shape, so the
later result does not retrospectively classify those earlier requests.

At `4702915ccddbc6aaa9feb18282fb01451eb85a91`, the
[preceding correction job](https://github.com/alcimerio/ai-config-selector/actions/runs/35363616409/job/105660790373)
passed the shared gates, both paired catalogs, and the first three corrected
hook repetitions (8.43, 8.69 and 9.02 seconds). All three installed-discovery
cases failed before the startup-prerequisite correction.

At `e897b57c8ba7dc68fabd9ed980e0d820a04a2e42`, the
[preceding native job](https://github.com/alcimerio/ai-config-selector/actions/runs/35360789038/job/105651406882)
passed both catalog suites but failed discovery and all three hook repetitions
(5.38, 5.27 and 4.97 seconds); only the third reported an invocation marker.
An earlier single hook pass was observed at `91dae608` in
[its native job](https://github.com/alcimerio/ai-config-selector/actions/runs/35358006972/job/105642152984),
after the original receipt-unavailable failure.

The hook fixture had assumed that an editable initial screen implied receipt
publication. The corrected gate waits for a valid receipt before producing
first input and uses the existing ticker and deadline. Earlier error messages
discarded the underlying error category, so later passes cannot prove that all
prior failures were benign races or would eventually have succeeded.

Discovery diagnostics now distinguish an early Codex process exit from a slow
protocol response. Source comparison found that the direct fixture omitted the
exact optional system-requirements probe already supplied by the production
Codex executor. The Devin requests were known startup routes, with no model or
unknown route observed. After aligning the exact system-file probe and bounded
synthetic startup replies, both plugin cases passed. The earlier Codex hook
backend-request failure is retained as history; the latest run classified one
source-backed optional metadata request per fresh hook Session. No production
extension support follows.

The installed discovery definition is deliberately narrower than the product
matrix: it is a bounded black-box observation of target discovery and request
metadata, not public Profile activation or a general extension capability.

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
  environment and selected filesystem output destinations can reuse typed grants.
  Byte and time bounds are separate execution constraints.
- Target-owned overlay candidate: event/matcher, normalized-definition trust
  hash, shell/JSON serialization, timeout and decision/output semantics.
- Defer: prompt/agent hooks, async/background settlement, detached helper
  cleanup and binding target hook/trust definitions to selected executable-byte
  identity. Existing executable grants already bind selected bytes. Pinned
  command completion can permit a detached helper; no successful Codex hook
  execution observation is claimed.

### Devin hooks

- Common existing intent: the prepared SessionStart witness uses selected
  executable/input references, protected/outside operation checks and the
  existing ACS Session/MCP lifecycle.
- Target-owned overlay candidate: project `hooks.v1.json`, event/matcher,
  command shell ABI, event JSON, timeout and hook decision/output handling.
- Defer: complete cross-source merge precedence, prompt hooks, exit-2 versus
  other-error policy beyond the documented table, detached-child cleanup and
  fail-open behavior as ACS enforcement. One native observation passed and
  established the selected hook's observed physical effects; an earlier
  receipt-unavailable failure and three later failures remain recorded. The
  corrected gate subsequently passed three fresh native cases. Diagnostic
  publication is best-effort; absence cannot prove non-invocation.

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
step with explicit opt-in. One promoted run passed and established the
selected hook's observed physical effects; an earlier run failed before a
valid receipt, and three later repetitions also failed. The corrected gate
subsequently passed three fresh native repetitions; earlier erased error
categories prevent attributing every past failure to the same cause. A fixed-code diagnostic sidecar offers
best-effort invocation/stage context without exposing event data or paths;
absence of a diagnostic or receipt cannot prove non-invocation.

## Native hook assessment status

The test-only Devin hook harness prepares a project `SessionStart` definition,
explicit hook executable reference, bounded event input, selected-input read,
protected-config/outside write-denial attempts, atomic exclusive receipt
publication, PID/PPID/session/executable/input evidence, and a first-input gate.
Existing MCP, public ACS, live-session, natural-exit and descendant checks remain
unchanged. The native glue now validates the receipt before successful
completion acknowledgement. One native run passed, while an earlier failure
before a valid receipt remains unexplained and three subsequent repetitions
also failed before the correction. The revised gate keeps first input pending
only for genuine missing receipt/marker leaves, uses the existing ticker and
deadline, and refuses unsafe or malformed proof immediately. Its portable
regression and three fresh native repetitions passed; that evidence does not
explain every prior failure.
Independently reviewed source is not runtime evidence. MCP evidence is not
presented as hook-child cleanup evidence.

The assessment invocation is deliberately separate from normal gates:

```text
ACS_RUN_NATIVE_DEVIN_HOOK_ASSESSMENT=1 \
  ACS_TEST_DEVIN_BINARY=<locked Devin member> \
  ACS_TEST_DEVIN_ARCHIVE=<locked archive> \
  ACS_PROMOTED_BINARY=<promoted ACS> \
  ACS_PROMOTED_VERSION=<version> \
  ACS_PROMOTED_SANDBOX_BACKEND=available \
  go test ./acceptance -run '^TestPromotedArtifactNativeDevinSessionStartHook$' -count=3 -v -timeout=12m
```

This command is the exact separate CI invocation; it is not part of the release
workflow or mandatory MCP gate. The step discovers the named test, sets the
explicit opt-in and locked target paths through environment values, and applies
a bounded Go timeout. Receipt PID/PPID fields are structural evidence; they do
not establish independent process ancestry, natural hook exit, or detached hook
cleanup. A passing observation proves only the tested hook event
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

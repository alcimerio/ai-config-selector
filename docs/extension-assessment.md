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

## Decision matrix

| Concept / target | Pinned contract and discovery | Authority and lifecycle | Decision and prerequisites |
| --- | --- | --- | --- |
| Codex plugin | Root `plugin.json` and OpenAI overlay precedence are target-owned; package capabilities include Skills, MCP and hooks. | Plugin hooks use target trust; plugin root/data and installed lifecycle are additional authority. ACS currently disables Codex plugins. | Consider only an identity-pinned local package overlay. Exclude marketplace, dependencies, remote auth, updates and persistent data until native discovery, trust and cleanup are proven. |
| Devin plugin | Manifest precedence is `.devin-plugin`, `.claude-plugin`, then root; local installs are live-linked. Governance and managed manifests have fail-open cases. | Plugins may add rules, MCP, hooks, agents and persistent `PLUGIN_DATA`; this is not equivalent to a disposable Session. | Consider only explicit local activation with common grants for selected resources. Defer Cloud sync, credentials, dependencies, updates, governance and persistent data. |
| Codex hook | Pinned source defines layered discovery, normalized-definition trust hashes, command/MCP handlers, SessionStart and other lifecycle events. Normal command completion can leave detached helpers. | Common grants can cover selected executable/input/MCP references; trust, shell ABI, event timing and output decisions remain target-owned. | Pending a separate Codex prototype. The current opt-in harness is Devin-only; async/background support remains deferred until settlement is proven. |
| Devin hook | Pinned docs define project `hooks.v1.json`, event JSON, command output/decisions, SessionStart before the first prompt, and incomplete cross-source merge details. Exit semantics distinguish success, block and logged errors. | Hook fail-open/timeout/child semantics are target behavior, not ACS enforcement. | The current opt-in harness assesses one bounded project SessionStart witness through public ACS composition. No hook schema is shipped. |
| Codex role/agent | Pinned role application is a typed allowlist of model/prompt/personality/service-tier and feature/Skill controls. It preserves parent authority. | Roles do not add arbitrary filesystem, environment, network, credential or sandbox authority; threads are not necessarily OS processes. | A narrow descriptive role overlay is a future candidate. Reject unsupported authority fields and defer model-assisted/native lifecycle claims. |
| Devin custom agent | Pinned Markdown agents support model, prompt, `allowed-tools` and `max-nesting`; default tool access is all, background agents inherit approvals, and parent interruption parks agents. | Target tool policy is not an OS grant; no independent per-agent filesystem/env/network/cleanup lease is documented. | Consider only a target-owned identity/prompt/tool overlay after bounded selection and lifecycle evidence. Keep parent ACS grants as the OS boundary. |

For every row, discovery/precedence, trust, executable and filesystem effects,
environment/secrets, network, project inheritance, failure precedence and
descendant cleanup remain separate questions. Compile-only or parser results do
not establish runtime containment.

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

Codex roles are narrower than target tool permissions: pinned `role.rs` applies
typed model/prompt/personality/service-tier and feature/Skill controls while
preserving parent authority. It does not establish arbitrary role filesystem,
environment, network, credential or sandbox authority. Devin custom agents
have the opposite important default: documented `allowed-tools` defaults to
all, background agents inherit approvals, and parent interruption parks rather
than kills them. Neither target's role/agent behavior is an ACS OS lease.

Pinned Devin documents describe `.devin-plugin/plugin.json`, local live-linked
installs, project/user/plugin precedence, `.devin/hooks.v1.json`, command-hook
event JSON, and `.devin/agents` Markdown definitions. The bundled archive
members are `extensibility/plugins/overview.mdx`,
`extensibility/plugins/quickstart.mdx`, `extensibility/hooks/overview.mdx`,
`extensibility/hooks/lifecycle-hooks.mdx`, and `subagents.mdx`. Their documented
contracts include plugin-hook fail-open behavior, managed-manifest fetch failure
dropping forbids, custom-agent default-all tools, inherited background
approvals, and parked parent interruption. Missing complete cross-source merge
algorithms and unspecified child settlement remain evidence gaps; they are not
filled by this assessment.

Current primary portable contracts are also documented in [OpenAI plugin
packaging](https://developers.openai.com/plugins/build/plugins), [Codex
hooks](https://learn.chatgpt.com/docs/hooks), and [Codex
subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
Those pages may describe newer behavior than the locked binaries and are not
runtime proof.

## Current ACS boundary and evidence

ACS production composition currently supports typed Skills, instructions,
workspace, paths, executables, environment references and reference-only MCP.
The assessment tests assemble a real Devin Profile through those codecs and
`ResolveSyntaxFor`, preserving MCP argument/environment/filter references and
refusing an unbound executable reference. A second production test resolves
both the MCP and hook executable references. These are compiler-composition
tests, not target execution proof.

Current constraints remain explicit: Codex plugins are disabled in production
semantics/projections; MCP environment names select references but do not narrow
helper inheritance; outbound network authority is coarse; and there is no
independent per-agent filesystem, environment, secret, network or descendant
lease. Unknown or unsupported extension fields must fail closed rather than
disappear.

The public dry-run probes for invented plugin, hook and agent overlay fields are
structural rejection tests only. The native hook test is opt-in and remains
disabled pending independent review. No target execution is claimed here.

## Native hook assessment status

The test-only Devin hook harness prepares a project `SessionStart` definition,
explicit hook executable reference, bounded event input, selected-input read,
protected-config/outside write-denial attempts, atomic exclusive receipt
publication, PID/PPID/session/executable/input evidence, and a first-input gate.
Existing MCP, public ACS, live-session, natural-exit and descendant checks remain
unchanged. The native glue now validates the receipt before successful
completion acknowledgement. The experiment remains unrun and independently
reviewed source is not runtime evidence. MCP evidence is not presented as
hook-child cleanup evidence.

The planned invocation is deliberately separate from normal gates:

```text
ACS_RUN_NATIVE_DEVIN_HOOK_ASSESSMENT=1 \
  ACS_TEST_DEVIN_BINARY=<locked Devin member> \
  ACS_TEST_DEVIN_ARCHIVE=<locked archive> \
  ACS_PROMOTED_BINARY=<promoted ACS> \
  ACS_PROMOTED_VERSION=<version> \
  ACS_PROMOTED_SANDBOX_BACKEND=available \
  go test ./acceptance -run '^TestPromotedArtifactNativeDevinSessionStartHook$' -count=1 -v
```

This command is proposed CI wiring only, not an enabled workflow entry. Before
execution, independent review must clear the generated profile, receipt reader,
pre-acknowledgement verification, Session identity correlation, hook settlement
and all negative cases. Receipt PID/PPID fields are structural evidence; they
do not establish independent process ancestry, natural hook exit, or detached
hook cleanup. Native success would prove only this documented synchronous hook
event and its observed physical grant effects under the tested public ACS/MCP
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

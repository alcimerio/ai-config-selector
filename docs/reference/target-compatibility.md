# Target compatibility

[Documentation index](../README.md)

ACS admits only exact `codex-cli 0.149.1` and `codex-cli 0.156.0` version
outputs. Prereleases, nearby versions and unknown versions fail closed before
login, status or interactive execution. Callers cannot override this policy.
The immutable plan names the complete reviewed set, so its authority digest
changes when that set changes. Stored Profile and authentication record versions
remain unchanged.

Both versions use the same ACS recipe: file credentials in the private Session,
forced ChatGPT identity and workspace, fixed provider and entrypoint, untrusted
project configuration, disabled plugins/apps and externally contained execution.
ACS keeps ownership of containment, process settlement and projection readback.
The named identity validator still rejects unsupported authentication shapes;
new upstream authentication mechanisms do not become supported automatically.
The separate optional extension/plugin discovery experiment remains pinned to
0.149.1. Adding another registered runtime does not extend that experiment.

The [official tagged configuration](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/core/src/config/mod.rs),
[file authentication storage](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/login/src/auth/storage.rs)
and [execution configuration](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/core/src/exec_env.rs)
were compared with the corresponding `rust-v0.149.1` sources. Review covers the
ACS recipe, not every upstream feature. Native acceptance uses the checksum
locks in `scripts/codex-test-targets.lock`, including each matching sibling
code-mode host. Schema comparison alone is not compatibility proof.

Codex 0.156.0 may show a folder-access prompt despite `approval_policy=never`.
Selecting **Open restricted** preserves ACS's forced untrusted configuration;
ACS does not approve this onboarding prompt automatically
([tagged onboarding](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/tui/src/onboarding/trust_directory.rs)).
It also loads account workspace requirements and may route to an account-selected
HTTPS backend after the fixed ChatGPT entrypoint
([tagged routing contract](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/app-server/src/request_processors/account_processor/workspace_routing.rs)).
ACS retains its existing coarse outbound-IP authority boundary; fixing the
entrypoint does not pin every target request to one URL.

The installer retains its four-argument interface with `0.149.1` as the default.
A fifth argument selects either exact reviewed version. It validates all lock
rows and complete CLI/host pairs before staging either executable. The fetcher
requires both reviewed pairs and verifies each downloaded archive digest.
Promoted candidate and release native matrices validate the same supplied ACS
bytes against both targets. See [testing](../development/testing.md) for the
synthetic authentication, isolated Keychain and recovery coverage. Real account
login, hosted inference and daily-use authentication remain outside automated
acceptance.

Codex 0.160.0 was reviewed but remains unsupported: native startup fails while
synchronizing managed preferences under the existing ACS confinement. The
[upstream application-policy change](https://github.com/openai/codex/commit/22a3f6d5d89c026c6b4f606ae5604f9e00059b23)
introduced this strict prerequisite. ACS does not bypass it or add host preference
authority to admit that target.

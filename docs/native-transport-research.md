# Native transport research probes

[Documentation index](README.md) · [Contributor test setup](../CONTRIBUTING.md#research-harnesses)

These isolated tests measure a bounded transport matrix on macOS 26 Apple
Silicon. They do not change ACS runtime policy, public commands, Profile
schema, grants, or target composition. They also do not establish that ACS is
an egress firewall.

The [Native transport research workflow](../.github/workflows/native-transport-research.yml)
creates disposable,
independently ready listeners and first reaches each one with a unique positive
control. A descendant then attempts numeric IPv4 and IPv6 TCP and UDP, plus two
Unix-socket paths, under the current coarse policy, a policy with outbound
allowances removed, and the smallest accepted exact endpoint or path rules.
Every case records the policy compiler result, operation name and marker,
bounded client error category, bytes written, exact listener receipt, and
authenticated process-tree cleanup where ACS launches the case. A separate
helper carries connected TCP and UDP descriptors to the point immediately
before the production descriptor sealer, executes that sealer, and proves the
target cannot write the markers after exec.

The job uploads `native-transport-evidence-<commit>` as a no-overwrite JSON
record. It includes the exact commit and tree, job name, macOS product and build
versions, architecture, and SHA-256 of the native test helper. Policy rejection
is a measured research result: the record retains the sanitized minimal rule
and does not turn rejection, timeout, connection refusal, or absent receipt
into an enforcement claim.

The workflow retains the artifact for 14 days. Preserve its verified JSON and
source/run identity privately if it is needed after that retention window; a
missing artifact is not a passing observation.

Run the probe and its evidence-classification tests only on the disposable native
runner. The command below matches the workflow:

```sh
ACS_RUN_NATIVE_TRANSPORT_PROBE=1 \
ACS_NATIVE_TRANSPORT_EVIDENCE="$RUNNER_TEMP/native-transport-evidence.json" \
ACS_NATIVE_TRANSPORT_JOB="Native transport research / Transport probes (darwin/arm64)" \
go test -count=1 -v -timeout=8m ./internal/launch \
  -run '^(TestNativeSeatbeltTransportResearchMatrix|TestSeatbeltTransport.*)$'
```

This matrix does not exercise a Network Extension. Provider activation and
ordering, standalone Session attribution, real QUIC, hostname DNS and
rebinding, redirects, proxy behavior, TLS identity, actual child-CLI
compatibility, fail-closed mediator lifecycle, and comprehensive destination
enforcement remain unresolved. Do not infer comprehensive network destination
enforcement from this bounded transport matrix.

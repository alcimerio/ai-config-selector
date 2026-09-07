# Native transport research probes

These isolated tests measure a bounded transport matrix on macOS 26 Apple
Silicon. They do not change ACS runtime policy, public commands, Profile
schema, grants, or target composition. They also do not establish that ACS is
an egress firewall.

The dedicated `Native transport research` workflow creates disposable,
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

Run the probe only on its disposable native runner:

```sh
ACS_RUN_NATIVE_TRANSPORT_PROBE=1 \
ACS_NATIVE_TRANSPORT_EVIDENCE="$RUNNER_TEMP/native-transport-evidence.json" \
ACS_NATIVE_TRANSPORT_JOB="Native transport research / Transport probes (darwin/arm64)" \
go test -count=1 -v -timeout=8m ./internal/launch \
  -run '^TestNativeSeatbeltTransportResearchMatrix$'
```

This matrix does not exercise a Network Extension. Provider activation and
ordering, standalone Session attribution, real QUIC, hostname DNS and
rebinding, redirects, proxy behavior, TLS identity, actual child-CLI
compatibility, fail-closed mediator lifecycle, and comprehensive destination
enforcement remain unresolved. The result therefore cannot be used as a full
network GO or blanket NO-GO; it only informs the next separately reviewed
architecture decision.

# Outbound network enforcement investigation

Status: research decision for a separately reviewed native prototype. This is
not a supported feature, a production design, or evidence that destination
filtering works. The current product contract remains unchanged: ACS permits
coarse outbound IP and macOS resolver access, and **ACS is not an egress
firewall**.

## Boundary and result

This assessment covers macOS 26 on Apple Silicon only. It inspected commit
`4ebd62506a25b650c0c7a0b19a84b06c8c875a4a`, tree
`ef6703903501b42e156ab2691480ee2d444fbf3d`, including:

- `internal/launch/seatbelt_darwin.go`, whose default-deny policy allows local
  IP bind, all remote IP outbound connections, and the mDNSResponder Unix
  socket;
- `internal/launch/sandbox.go` and `internal/authority/plan.go`, whose single
  resolved runtime authority reports that coarse mode and explicitly reports
  destination filtering as unsupported;
- `internal/authority`, `internal/genericrun`, and `internal/executor`, where
  the resolved authority and fixed or literal executable identity feed the
  shared contained-process lifecycle;
- `internal/launch/seatbelt_supervisor_darwin.go`, which seals inherited file
  descriptors, supervises descendants, and produces cleanup proof; and
- `internal/launch/session.go` and `internal/sessionops`, which retain,
  quarantine, inspect, and conservatively recover durable Session ownership.

This research supports requesting independent design review for a bounded
native feasibility prototype; it makes no final prototype go/no-go decision
and is **NO-GO for production work or a support claim**. Apple documents a
transparent proxy API that receives TCP and UDP flows and can copy them through
provider-owned connections, but the required Session attribution, fail-closed
provider lifecycle, DNS behavior, complete flow coverage, and target
compatibility have not been observed on macOS 26. No reproducible
required-property blocker has yet justified a final prototype no-go.

## Evidence classification

Statements in this document use these labels:

- **Documented** — an API or protocol contract in a linked primary source.
- **Source-observed** — behavior visible in the exact ACS source boundary
  above; it is not native execution evidence.
- **Hypothesis** — a design claim that a native probe must confirm.
- **Unproven** — no acceptable evidence exists yet.

Apple documents App Sandbox as kernel-enforced access control and exposes only
coarse outgoing-client and incoming-server entitlements. That documentation
does not promise an App Sandbox or Seatbelt destination allowlist
([App Sandbox configuration](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox),
accessed 2026-09-07). **Documented.** ACS's generated SBPL currently uses the
broader `(remote ip)` rule. **Source-observed.** Any narrower SBPL predicate is
therefore an experiment, not an architecture contract.

Apple documents `NEAppProxyProvider` as a transparent proxy for socket flows
selected by app rules, including TCP, UDP, and some DNS flows
([NEAppProxyProvider](https://developer.apple.com/documentation/networkextension/neappproxyprovider),
accessed 2026-09-07). Apple separately documents that a transparent provider
may accept and copy a flow or return `false`, in which case the operating
system communicates directly with the ultimate destination
([NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider),
accessed 2026-09-07). Consequently a Session flow must never take that bypass
branch. **Documented.**

Apple's flow-copying guide says the provider receives an intended remote
endpoint, creates the remote `NWConnection`, copies data in both directions,
and must bound buffering and close both sides on completion or error
([Handling Flow Copying](https://developer.apple.com/documentation/networkextension/handling-flow-copying),
accessed 2026-09-07). `NEAppProxyFlow.remoteHostname` is populated for
connect-by-name APIs such as URLSession and Network.framework, but that does
not say every resolver or socket API supplies a hostname
([remoteHostname](https://developer.apple.com/documentation/networkextension/neappproxyflow/remotehostname),
accessed 2026-09-07). **Documented.** Full coverage of the child CLIs is
**unproven**.

Transparent proxy settings route traffic according to included and excluded
network rules, with exclusions taking priority. The documented included-rule
restrictions give DNS special treatment and permit TCP, UDP, or either
([includedNetworkRules](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules),
[rule protocols](https://developer.apple.com/documentation/networkextension/nenetworkrule/protocol),
accessed 2026-09-07). This supports a catch-and-mediate hypothesis; it does not
prove that one configuration captures every IPv4, IPv6, DNS, loopback, and
private-address flow used by ACS descendants. **Documented plus hypothesis.**

Network Extension requires the corresponding entitlement. For direct
Developer ID distribution, Apple documents the system-extension entitlement
values; its deployment technote says transparent proxy providers can be
packaged as macOS system extensions from macOS 10.15
([Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension),
[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
revised 2025-08-19, accessed 2026-09-07). Activation may require explicit user
approval and remains pending until the user acts
([system-extension approval](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequestdelegate/requestneedsuserapproval%28_%3A%29),
accessed 2026-09-07). These are deployment costs, not permission to install or
activate anything during this investigation. **Documented.**

## Threat model and semantic contract

### Protected assets

The enforcement boundary protects the selected destination policy, Session
identity and generation, mediator control channel, other Sessions, unrelated
local/private services, and the guarantee that no workload byte reaches a
non-authorized transport destination. Credentials and target output retain
their existing contracts; destination enforcement would not make either
trustworthy.

### Attacker powers

Treat the contained target, every descendant it creates, loaded Skill content,
and workspace content as malicious. They may:

- open TCP and UDP sockets with IPv4 or IPv6 literals; use system, custom, TCP,
  UDP, encrypted, or hard-coded DNS; use QUIC; follow redirects; and repeat
  resolution to exploit rebinding;
- address loopback, link-local, private, multicast, broadcast, and public
  ranges; connect to Unix sockets; choose unusual ports; disable TLS
  verification; and speak arbitrary bytes over an allowed connection;
- fork, exec, double-fork, keep descendants alive after the leader exits,
  cancel at every transition, race cleanup, and overlap other Sessions;
- inspect all data intentionally placed in their environment, argv, files, and
  descriptors; copy or replay a Session token; and attempt to use another
  Session's endpoint or generation; and
- exploit inherited connected descriptors unless ACS proves they were closed
  before exec.

The model assumes macOS and the Network Extension framework enforce their
documented contracts, ACS and the external mediator are trusted, and the host
administrator is not hostile. A hostile administrator, kernel compromise,
physical network adversary, or compromise of the mediator is out of scope.
Same-user ambient processes are in scope for endpoint theft and replay: knowing
an endpoint or bearer value alone must not authorize a flow.

### Requested and enforceable destinations

A request is a tuple `(Session generation, source process, transport,
requested host, requested port)`. A host may be a canonical DNS name or an IP
literal. Wildcards, implicit ports, search-domain expansion, and URL-path rules
are outside the first prototype.

The enforceable transport decision is `(source process identity, TCP|UDP,
concrete IPv4|IPv6 address, port, Session generation)`. For a DNS name, the
mediator must receive the original name or own the resolution, validate the
name before resolution, reject disallowed address classes, and bind one
authorized answer set to one connection attempt. A later resolution is a new
decision. An IP literal is never reclassified as a permitted name. Redirects
have no inherited authority: each new connection is independently decided.

This contract does not treat a DNS name as cryptographic server identity. A
byte-copying transparent proxy selects the remote endpoint, but an adversarial
client can disable certificate validation and an allowed server can relay
arbitrary traffic. TLS identity remains the target TLS stack's responsibility
unless a later design explicitly terminates and re-originates TLS. RFC 9525
requires clients to match the reference identity against authenticated
identifiers and abort on mismatch
([RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), March 2024). Such TLS
termination would change authentication, certificate, privacy, and target
compatibility semantics and is not silently included here. If the required
product meaning of “destination” includes ACS-enforced TLS peer identity, that
is a deterministic no-go for this transparent byte-relay design.

## Explicit evidence limits

- No native network probe was run in this investigation. Source inspection on
  Linux is not macOS evidence, and policy text is not enforcement evidence.
- No Network Extension was built, provisioned, installed, activated, or
  removed. Entitlement availability and user approval remain prerequisites.
- Apple documents source-process audit identity for content-filter flows, but
  the equivalent exact descendant identity needed by the proposed transparent
  proxy flow is unresolved. App signing identity alone cannot distinguish two
  concurrent executions of the same child CLI.
- The documented rule APIs and DNS notes do not establish exhaustive capture
  for the bypass corpus below. That is a native observation obligation.
- No real Devin or Codex destination, account, credential, external service,
  or one-week daily-use observation was used. Target compatibility is pending
  deterministic credential-free native fixtures and is separate from the
  prepared release candidate.
- The design enforces a transport destination if proved. It does not constrain
  application bytes sent to an allowed endpoint, prevent that endpoint from
  relaying them, or make target output and remote services trustworthy.

## Candidate architectures

| Option | Assessment |
| --- | --- |
| Narrower Seatbelt destination predicates | Reject as the enforcement architecture. No cited Apple contract supplies stable hostname/address/port semantics; DNS answers change, and policy text cannot itself prove redirect, rebinding, UDP/QUIC, or target behavior. A disposable probe may establish a transport-denial observation only. |
| Proxy environment variables | Reject as enforcement. A hostile workload can ignore or remove them. Combining them with denied direct IP access could be useful for a cooperative compatibility experiment, but it still requires a kernel-enforced path to a controlled mediator and does not transparently cover arbitrary UDP/QUIC. |
| Session-local listener or Unix socket | Reject as the complete architecture. It is narrow and can be authenticated, but ordinary child CLIs are not known to route every TCP/UDP operation through a custom local protocol. A loopback listener also needs a proved rule that allows only that endpoint. |
| Content or packet filter | Reject for the mandatory-mediator contract. A pass verdict lets the workload communicate with the destination; the filter does not exclusively own and copy the allowed connection. It may be defense in depth, not the sole authority. |
| `pf`, route changes, packet tunnel, or a privileged daemon | Reject for this prototype. They mutate host-global networking or add privilege, have weak Session/process attribution, and expand the reviewed boundary. Apple also directs selective traffic proxying to transparent proxy rather than packet tunnel ([TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers), revised 2025-07-22, accessed 2026-09-07). |
| Transparent proxy Network Extension plus current Seatbelt | **Leading candidate for design review.** It is application-transparent and provider-owned flow copying covers documented TCP and UDP shapes. Session attribution, exhaustive capture, fail-closed loss, and DNS/name behavior remain native gates; failure of an early deterministic gate can stop it before full implementation. |

## Smallest full-property prototype

The prototype is an isolated test application containing an
`NETransparentProxyProvider` system extension, a minimal authenticated control
agent, and disposable probe executables. It is not linked into the ACS CLI and
does not add Profile or command syntax.

1. The existing immutable resolved authority produces a test-only destination
   policy and a random Session generation/challenge before any target starts.
   The exact same object drives mediator admission, Seatbelt preparation,
   launch verification, and cleanup expectations.
2. The control agent sends that policy over a mutually authenticated private
   channel to the provider. Admission includes the exact ACS Session ID,
   generation, challenge, and process identity ledger; acknowledgements are
   challenge-bound and monotonic. Endpoint knowledge or a copied token is
   insufficient.
3. The provider installs the smallest documented outbound TCP+UDP rule set that
   can claim candidate traffic. It starts in deny-by-default state for a
   registered Session. Every matching Session flow returns `true`; returning
   `false` is a test failure because Apple documents that as direct bypass.
4. For every flow, the provider validates the source audit identity against a
   fresh, stable ACS descendant identity and the active generation. Apple
   documents an audit token identifying the process that created a filter flow
   ([sourceProcessAuditToken](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceprocessaudittoken),
   accessed 2026-09-07), but equivalent usable identity on the chosen proxy
   flow and race-free descendant binding are **unproven** and are early gates.
5. The provider normalizes the requested endpoint, resolves names under the
   stated contract, rejects unapproved name/address/port/protocol combinations,
   opens the remote connection itself, and copies bounded data. It never asks
   the workload to honor proxy variables. Provider-created connections must be
   proven not to recurse into or bypass another Session decision.
6. Seatbelt remains default-deny for filesystem, IPC, and descendants. The
   prototype removes the current coarse IP and mDNS grants only in its
   disposable policy. The Network Extension, not an environment convention,
   is the sole path from the workload to an allowed transport endpoint.
7. Cancellation or any lost control/provider state closes both sides of every
   flow, rejects new flows, revokes the generation, waits for provider proof,
   then permits the existing Session cleanup. Uncertain provider cleanup keeps
   the Session and policy generation quarantined just as uncertain process
   cleanup does now.

The prototype requires a dedicated disposable macOS 26 Apple Silicon host,
Developer ID/provisioning that legitimately includes the required entitlement,
explicit activation approval, no external accounts or credentials, and only
local deterministic endpoints. Installing or activating the extension is a
separately reviewed action; it was not done by this research.

## Required native evidence matrix

Every probe records independent operation witnesses: provider admission and
decision IDs, source audit identity, requested and concrete endpoints, remote
listener receipt or absence, returned error, process cleanup, flow closure,
generation revocation, and physical Session removal or quarantine. A test name,
policy string, exit zero, timeout alone, or fixture literal is not evidence.

| Property | Required macOS 26 Apple Silicon probe and pass condition | Current state |
| --- | --- | --- |
| Direct IPv4 and IPv6 | Separate local TCP listeners on `127.0.0.1` and `::1`; approved tuples receive unique bytes through provider-owned connections, while wrong address and port receive no listener marker. Repeat with numeric literals and connect-by-name. | Unproven |
| Alternate DNS | Disposable UDP and TCP DNS endpoints plus a resolver witness. Raw port-53, custom resolver, system resolver, and connect-by-name attempts must all be mediated or denied; only mediator-authorized answers may lead to a connection. | Unproven; Apple documents special DNS rule behavior, not this coverage |
| UDP | Local datagram echo with per-datagram IDs. Approved UDP arrives through a provider decision; denied UDP produces no server marker. | Unproven |
| QUIC | A real local QUIC client/server completes a cryptographic QUIC handshake and request for the approved case, and produces no server handshake witness for the denied case. QUIC uses UDP but has its own handshake and connection semantics ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), May 2021). A generic UDP send/timeout is transport-denial evidence only, never QUIC compatibility. | Unproven |
| Redirects | A local HTTP origin returns redirects to approved and denied second origins. The client follows them; each hop has a distinct provider decision, and the denied listener sees nothing. | Unproven |
| DNS rebinding | Authoritative local DNS returns approved then denied loopback addresses with zero TTL for the same name. Each resolution/connection is newly authorized, the first selected address is pinned for that attempt, and the second listener sees nothing. | Unproven |
| Local and private addresses | Probe loopback v4/v6, the host's existing private interface address without changing configuration, and representative multicast/broadcast attempts. Default is deny; each approved exception is exact and witnessed. | Unproven |
| Unix sockets | One test control socket is allowed; unrelated Session and host Unix sockets are denied and receive no marker. The network provider is not credited for Seatbelt's Unix-socket decision. | Existing coarse source rule observed; revised policy unproven |
| Descendants | Parent, child after exec, double-forked descendant, and descendant surviving leader exit each open approved and denied flows. Every source identity binds to the same live Session; no descendant bypasses or outlives cleanup. | Process supervision exists in source; network attribution unproven |
| Inherited connected descriptors | Start with a connected TCP and UDP descriptor in the launcher, run the existing descriptor sealer, and attempt unique writes after exec. No remote marker arrives; sealer and target report the descriptor absent. | Sealer exists in source; native network regression required |
| Proxy bypass and loss | Ignore/clear all proxy environment variables and use raw sockets: mediation still occurs. Kill or crash the control agent/provider before open, during open, and during an established flow: new traffic fails closed and active remote sides close within a fixed bound. | Unproven |
| Cancellation and cleanup | Cancel at policy admission, target start, DNS, connect, active copying, and leader exit. No process, provider flow, remote connection, rule generation, or Session remains; uncertainty produces durable quarantine rather than deletion. | Existing process lifecycle is source-observed; provider composition unproven |
| Concurrent Sessions | Two Sessions use opposite policies and unique challenges concurrently. Each can reach only its own allowed endpoint; policy update, cancellation, and cleanup of one do not alter the other. | Unproven |
| Endpoint theft and replay | A same-user non-descendant and the other Session copy endpoint metadata and bearer bytes, race current admission, and replay after revocation. Provider rejects them by stable source identity plus Session generation; all remote listeners remain silent. | Unproven; bearer-only design is forbidden |
| TLS identity | Local CA issues correct-name, wrong-name, and expired certificates. A normal client must accept only the correct certificate, proving compatibility, while the report states whether validation occurred in the client or mediator. Do not claim ACS enforcement from client behavior. If ACS-enforced peer identity is required, demonstrate mediator-side authenticated name verification without weakening target TLS; otherwise mark unsupported. | Transport endpoint can be tested; ACS-enforced TLS identity unsupported by this design |
| Target compatibility | Run the locked, supplied Devin and Codex artifacts without credentials against deterministic local protocol fixtures using their real launch paths. Observe TCP, DNS, UDP/QUIC if used, terminal behavior, cancellation, and exact target errors. No environment-only happy path qualifies. | Unproven; external service behavior and credentials are excluded |

All negative probes have an explicit readiness marker before the attempted
operation, a short deterministic deadline, a remote absence witness independent
of client error text, and cleanup in a finally/defer path. The harness records
the exact promoted prototype artifact digest and operating-system build. It
must restore the pre-test extension configuration and prove that restoration;
otherwise the native job fails and the host is quarantined.

## Frozen go/no-go rubric

This rubric is immutable for the first prototype review. Changing a required
property or accepting weaker evidence requires a new research decision; it may
not turn a red result green on the prototype branch.

**GO to implementation design review** only if one exact prototype head on
macOS 26 Apple Silicon passes every applicable matrix row, with:

1. provider-owned mediation and independent remote operation witnesses for
   approved TCP, approved UDP, denied TCP, denied UDP, IPv4, IPv6, DNS,
   redirect, rebinding, local/private, real QUIC, Unix socket, descendant,
   inherited-FD, loss, cancellation, concurrency, theft, and replay cases;
2. stable Session/process attribution without PID-only or bearer-only trust;
3. fail-closed startup, update, provider crash, control loss, and cleanup, with
   durable quarantine on uncertainty;
4. exact requested-name-to-address semantics and explicit exclusion of TLS
   identity from the claim, or a separately accepted and proven TLS design;
5. credential-free deterministic compatibility evidence for the exact child
   CLI artifacts and no dependency on proxy environment compliance; and
6. a reviewed entitlement, activation, removal, privacy, signing, and
   distribution plan acceptable for the supported macOS-only product.

**STOP / NO-GO** rather than weaken the criteria when any of these deterministic
blockers is reproducible:

- a Session flow can take the transparent provider's direct path, including
  raw IPv4/IPv6, alternate DNS, UDP, QUIC, or a descendant;
- the provider cannot distinguish an active Session generation from another or
  from a same-user replay using a stable kernel-supplied identity;
- provider/control loss leaves a direct or still-forwarding connection, or
  cleanup can delete the Session before policy and flows are proved gone;
- documented rule limitations make exhaustive TCP+UDP v4/v6 and DNS capture
  impossible without host-global route/PF changes or an always-privileged
  service outside the accepted deployment boundary;
- either locked child CLI cannot operate through the enforced path without an
  unsupported target patch, TLS interception, credentials, or an environment
  convention that raw sockets bypass; or
- the accepted product requirement includes ACS-enforced TLS peer identity and
  no compatible authenticated mediation design proves it.

A platform API error, unsigned local build, missing entitlement, or absent
approval is not by itself a technical no-go; it is a prerequisite failure until
reproduced with correctly provisioned, approved artifacts. Conversely, policy
compilation, a happy-path request, an HTTP proxy environment variable, or one
blocked UDP packet is never a go result.

## Next reviewed task

Create one standalone native prototype repository or isolated test target that
implements only the seven-component flow above. Before coding, independent
review must freeze: the precise transport destination contract; provider rule
set; source audit-token and descendant-ledger binding protocol; monotonic
Session generation messages; fail-closed state machine; bounded flow-copy
buffers; deterministic local DNS/TCP/UDP/HTTP/TLS/QUIC fixtures; restoration
procedure; and matrix-to-witness mapping.

The task must produce an immutable prototype head and artifact digest, native
logs with sanitized operation witnesses, the exact macOS build, and a
property-by-property result. It must not add ACS CLI flags, Profile fields,
grants, proxy services, release claims, or automatic activation. A separate
root decision applies the frozen rubric to that evidence before any production
architecture work begins.

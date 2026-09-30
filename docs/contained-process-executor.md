# Contained process executor

[Documentation index](README.md) · [Architecture](architecture.md)

This is an implementation reference. For command use, see [generic
commands](generic-run.md), [interactive Codex](interactive-codex.md), and
[named Codex authentication](codex-auth.md). The supported runtime is macOS 26
on Apple Silicon.

`internal/executor` owns the protected Session lifecycle for the fixed
interactive shell, literal generic commands, the registered Devin lifecycle,
and named Codex authentication and interactive execution. Its production
constructor selects the required native sandbox internally; adapters cannot
provide a backend, probe ordering, Session retention, or cleanup policy.

`RunCommand` accepts one immutable declarative command resolved by ACS plus a
common authority plan. It adds no adapter callback or process handle. The
executor repeats executable identity validation after Session materialization
and immediately before native preparation, then uses the shared attached
settlement path. Generic execution selects no target overlay or target-auth
projection and adds no inferred authority beyond the common plan. Explicitly
selected environment values can still include secrets.

`RunShell` accepts only Session and working directories, target-independent
Profile materialization, and terminal streams. It checks the native sandbox,
creates and materializes a Session without target-auth projection, prepares exactly
`/bin/zsh -f`, retains it before Start, and settles the process once.

A failed Start is not waited. A successful Start is waited exactly once, but a
returned Wait is not proof that descendants are gone: an open cleanup signal
keeps the Session leased until later confirmation. Bounded cleanup uncertainty
and Session finalization failures take precedence over an ordinary shell exit,
so the facade reports infrastructure status rather than a potentially unsafe
target status. Readiness and shell planning create no Session and start no
requested target; the bounded native-backend readiness probe can execute the
fixed system helper. This differs from process-free `acs doctor` inspection.

`RunDevin` accepts validated Devin configuration, resolved Profile
materialization, the independently selected Skills catalog, selected
instruction bundles, directories, and terminal streams. The executor captures termination and resize signals before
the sandbox check, creates and materializes the Session, copies only Devin's
fixed allowlisted credential file, runs `skills list --json` followed by `auth
status`, and, when instructions are selected, runs `rules list` and one `rules
show` per selected rule. It attaches the fixed interactive Devin invocation
only after these observations are interpreted. Selected environment values
are reserved for the attached target and its descendants, not these probes.
Catalog parsing remains in `devinruntime`; it keeps project and built-in treatment, canonical managed identities, and safe
redacted capability failures without exposing process output or credentials.
Before that interactive process is prepared or retained, the executor reserves
its signal-supervisor handoff under the supervisor lock. A termination already
pending rejects preparation; one received after the reservation is replayed
only after the required Start, so it cannot strand a retained Session.

`VerifyDevin` is the fixed protected preflight entrypoint for the opt-in
authenticated smoke. It performs Check, Session creation and materialization,
credential copy, ordered probes, settlement, and removal internally; it never
returns a Session path, process, retention lease, or execution callback.

Every registered process uses one private retained-process foundation with an
explicit probe, attached, or reserved Devin signal mode. Each process is
retained before Start. A failed Start is not waited;
a successful Start is waited exactly once, and cleanup uncertainty blocks the
next probe or target and retains the Session. The Devin adapter translates the
lower redacted preflight error to its existing public compatibility wrapper and
does not regain process lifecycle authority.

`codexauth.Registry` is a typed configuration and API facade only. The executor
acquires the named resource before taking one immutable executable snapshot,
creates the Session, publishes the exact marker generation, then protects it
for recovery before projecting credentials through `codexauthresource`. It runs
the fixed version plus login/status or interactive Codex commands, settles
cleanup proof, requests credential validation and finalization through the typed
resource, and removes the Session from the filesystem before marker deletion
and identity unlock. This is logical removal, not a claim of physical erasure
from storage media. Login remains Create-only; status, successful interactive
execution and recovery can replace only a valid changed projection with the same identity metadata.
Uncertain cleanup retains the protected Session and generation-bound marker,
and recovery never turns an interrupted Login into a credential record.

`codexauthresource` remains non-executing and owns credential validation,
Keychain access, locks, marker generations, secure projection/readback, and
commit/discard decisions. It imports neither the executor nor Session/process
packages. The facade never receives a provider, credential payload, lock,
marker writer, process, Session lease, or lifecycle callback.

Containment uses the resolved common workspace, path, executable-visibility
and environment authority plus the fixed runtime grants. It is not a network
egress allowlist or a separate per-tool/per-MCP-helper sandbox.

During the reserved startup handoff, resize notifications may coalesce but
cannot replace an already queued termination signal.

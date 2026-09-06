# Contained process executor

`internal/executor` owns the protected Session lifecycle for the fixed
interactive shell and the registered Devin lifecycle. Its production
constructor selects the required native sandbox internally; adapters cannot
provide a backend, probe ordering, Session retention, or cleanup policy.

`RunShell` accepts only Session and working directories, target-independent
Profile materialization, and terminal streams. It checks the native sandbox,
creates and materializes a credential-free Session, prepares exactly
`/bin/zsh -f`, retains it before Start, and settles the process once.

A failed Start is not waited. A successful Start is waited exactly once, but a
returned Wait is not proof that descendants are gone: an open cleanup signal
keeps the Session leased until later confirmation. Bounded cleanup uncertainty
and Session finalization failures take precedence over an ordinary shell exit,
so the facade reports infrastructure status rather than a potentially unsafe
target status. Passive readiness and shell planning remain side-effect free.

`RunDevin` accepts validated Devin configuration, resolved Profile
materialization, the independently selected Skills catalog, directories, and
terminal streams. The executor captures termination and resize signals before
the sandbox check, creates and materializes the Session, copies only Devin's
fixed allowlisted credential file, runs `skills list --json` followed by `auth
status`, and attaches the fixed interactive Devin invocation only after both
observations are interpreted. Catalog parsing remains in `devinruntime`; it
keeps project and built-in treatment, canonical managed identities, and safe
redacted capability failures without exposing process output or credentials.

Each probe and target is retained before Start. A failed Start is not waited;
a successful Start is waited exactly once, and cleanup uncertainty blocks the
next probe or target and retains the Session. The Devin adapter translates the
lower redacted preflight error to its existing public compatibility wrapper and
does not regain process lifecycle authority. Codex authentication remains on
its existing lifecycle in this stage.

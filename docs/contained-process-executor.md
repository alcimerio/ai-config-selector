# Contained process executor

`internal/executor` currently owns the protected Session lifecycle for the one
implemented shared operation: the fixed interactive shell. Its production
constructor selects the required native sandbox internally; adapters cannot
provide a backend, executable, arguments, probes, or Session projection.

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

This is only the shell foundation. Devin and Codex process lifecycles still use
their existing ownership paths and are intentionally not represented by a
generic executor API yet.

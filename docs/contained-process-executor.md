# Contained process executor

`internal/executor` owns the common protected Session lifecycle for fixed recipes:
check the native sandbox, create and materialize a Session, apply an allowlisted
projection, run ordered probes, retain every prepared process before start,
settle it once, and remove the Session only after backend cleanup proof.

Recipes contain executable intent, fixed arguments, optional probe arguments,
runtime inputs, and one allowlisted projection. They do not contain a backend,
native policy, process handle, or lifecycle callback. The fixed shell uses the
executor with exactly `/bin/zsh -f`, no projection, and no probes.

Target adapters remain responsible for interpreting their fixed probe output
and preserving target-specific diagnostics. The executor preserves the backend
contract that failed Start is not waited, successful Start is waited once, and
an open cleanup signal keeps the Session retained rather than treating target
exit as proof that descendants are gone.

# Verify Devin compatibility and skill isolation

ACS must verify adapter capabilities against the installed CLI instead of maintaining version allowlists. Its CI suite proves the adapter contract, and each launch runs a focused preflight that verifies the prepared ACS Session exposes exactly the selected global Skill Bundles while preserving a usable existing login. If either condition cannot be verified, ACS fails clearly rather than launching with weakened profile semantics.

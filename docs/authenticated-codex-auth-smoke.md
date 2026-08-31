# Optional authenticated named-authentication smoke

This is a supplemental trusted-host observation for behavior that the
credential-free `codex-cli 0.149.1` PR gate cannot honestly prove. It may
observe interactive login completion and target-origin token refresh with a
real account, but it must not run in CI and never replaces the arm64 and Intel
native merge gates.

## Preconditions

- Use a dedicated test account on a trusted macOS 26 host.
- Disable terminal recording, shell tracing, debug logging, and output capture.
- Build ACS from the exact reviewed commit and install the matching target from
  `scripts/codex-test-targets.lock` with the repository verification scripts.
- Start with a clean disposable identity name and verify no quarantined Session
  exists for it.

## Observation

From a normal terminal, run a browser or device login for the disposable name,
then run contained status. A refresh may be observed only when the target
naturally performs one; do not force, inject, copy, decode, compare, or print
tokens. Remove the disposable identity through the ACS logout command and
confirm that no leased Session or quarantine remains.

Record only the source commit, locked target digest, host architecture, command
category, and pass/fail result. Account identifiers, device codes, browser
URLs, target output, credentials, token timestamps, Keychain contents, homes,
Sessions, private paths, environment values, and generated policy must not be
recorded.

## Boundary

This smoke does not make account-dependent behavior deterministic and must not be recorded as
merge-gate evidence. A successful real login does not replace
the credential-free namespace, size, collision, locked-Keychain, isolation,
redaction, cleanup, or quarantine tests. A target-origin token refresh is
supplemental evidence only; if it does not occur naturally, report it as not
observed rather than altering credentials or weakening containment.

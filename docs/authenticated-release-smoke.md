# Optional authenticated Devin smoke

This is a local maintainer confidence check. It is supplemental to the
credential-free candidate gate on macOS 26 `darwin/arm64`; it never waives,
replaces, or weakens that gate.

The smoke may copy the existing Devin credential into an ephemeral Session and
start the real Devin CLI inside Seatbelt. Run it only on a trusted macOS host
from a normal terminal. Do not run it in CI or with a shared account.

## Preconditions

- The host is macOS 26 on Apple Silicon (`arm64`).
- `/usr/bin/sandbox-exec` is the verified system executable.
- Devin is installed and already authenticated.
- The repository worktree is clean and checked out at the candidate commit.
- Terminal recording, verbose shell tracing, and output capture are disabled.

## Run

Build the candidate without publishing it. Set `ACS_CANDIDATE_VERSION` to the
reviewed development identity (currently `v0.5.0` in the promoted workflow).
The same version string does not make a local build the published release;
record the exact source commit and candidate digest as well:

```sh
: "${ACS_CANDIDATE_VERSION:?supply the reviewed candidate embedded version}"
candidate_version="$ACS_CANDIDATE_VERSION"
scripts/release-candidate.sh "$candidate_version"
```

Install the matching local candidate into a temporary directory using the
candidate validator, then run a normal Profile launch from an ordinary terminal.
Do not print the credential, Session tree, environment, generated sandbox policy,
or Devin account output.

The accepted observation is deliberately narrow:

- sandbox readiness succeeded;
- Skill and authentication preflight succeeded;
- Devin reached its normal interactive lifecycle;
- exiting Devin returned control to the terminal;
- no leased Session remained after cleanup.

Remove the temporary install directory only after successful Session cleanup is
confirmed. If cleanup is uncertain, retain the compatible candidate executable
and private evidence for the [supported recovery procedure](manual-upgrade-recovery.md);
do not manually remove Session state. Record only the candidate version, source
commit, archive and installed-binary SHA-256, macOS architecture, and pass/fail
result in the release checklist.

## Safety boundary

The authenticated smoke proves neither artifact reproducibility nor release
immutability. It does not test Linux. It must not upload credentials, account
data, target output, Session contents, private paths, generated policy,
environment values, or terminal control characters to logs or artifacts.

If it fails, stop and diagnose locally. Do not weaken Seatbelt, bypass the
sandbox, copy additional host configuration, or treat a failing account-dependent
smoke as a passing observation. Record the failure separately from the credential-free native gate; neither result
substitutes for the other.

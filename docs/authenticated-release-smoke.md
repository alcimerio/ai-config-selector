# Optional authenticated Devin smoke

This is a local maintainer confidence check. It is supplemental to the
credential-free candidate gates on macOS 26 `darwin/arm64` and
`darwin/amd64`; it never waives, replaces, or weakens those gates.

The smoke may copy the existing Devin credential into an ephemeral Session and
start the real Devin CLI inside Seatbelt. Run it only on a trusted macOS host
from a normal terminal. Do not run it in CI or with a shared account.

## Preconditions

- The host is macOS 26 on arm64 or Intel.
- `/usr/bin/sandbox-exec` is the verified system executable.
- Devin is installed and already authenticated.
- The repository worktree is clean and checked out at the candidate commit.
- Terminal recording, verbose shell tracing, and output capture are disabled.

## Run

Build the candidate without publishing it:

```sh
candidate_version=v0.4.0
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

Destroy the temporary install directory after the observation. Record only the
candidate version, source commit, macOS architecture, and pass/fail result in
the release checklist.

## Safety boundary

The authenticated smoke proves neither artifact reproducibility nor release
immutability. It does not test Linux. It must not upload credentials, account
data, target output, Session contents, private paths, generated policy,
environment values, or terminal control characters to logs or artifacts.

If it fails, stop and diagnose locally. Do not weaken Seatbelt, bypass the
sandbox, copy additional host configuration, or publish the candidate based on
the credential-free gates alone.

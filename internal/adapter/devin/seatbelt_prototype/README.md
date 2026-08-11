# Seatbelt containment prototype

This throwaway prototype answers one question for issue #56: can ACS launch an
arbitrary process and its descendants through macOS Seatbelt while allowing the
working repository, an ephemeral Session, required system reads, network and
terminal behavior, but denying unrelated host files, inherited secrets and
Unix sockets?

Run it on macOS with:

```sh
go run ./internal/adapter/devin/seatbelt_prototype
```

The command creates only synthetic fixtures under a temporary directory. It
does not inspect the real home directory, credentials, configuration, or Unix
sockets. The prototype is not production code and must not be merged into
`main`; its final evidence belongs on issue #56 and this branch is its primary
source.

After the synthetic command passes, the machine owner may explicitly authorize
the credential-bearing preflight. Devin's output is discarded:

```sh
ACS_SEATBELT_PROTOTYPE_REAL_DEVIN=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS \
  go run ./internal/adapter/devin/seatbelt_prototype --real-devin-preflight
```

If that passes, run the interactive smoke from a private terminal:

```sh
ACS_SEATBELT_PROTOTYPE_REAL_DEVIN=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS \
  go run ./internal/adapter/devin/seatbelt_prototype --real-devin
```

This copies the existing Devin credential into a temporary Session, performs
sanitized preflight checks, launches Devin without capturing its terminal
output, and removes the Session after a normal exit. Never run this mode in CI
or redirect its output to a file.

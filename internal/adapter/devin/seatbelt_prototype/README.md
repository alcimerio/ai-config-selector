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

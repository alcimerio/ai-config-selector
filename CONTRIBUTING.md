# Contributing

ACS supports macOS 26 on Apple Silicon (`darwin/arm64`) using Seatbelt.
Unsupported hosts fail closed. Read the [architecture](docs/development/architecture.md)
before changing execution, capabilities or containment.

## Local setup

Install the Go toolchain specified in [go.mod](go.mod), clone the repository,
and run these checks on a supported Mac:

```sh
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/acs
```

CI selects the exact version in `go.mod`; newer toolchains can produce different
release bytes. Format changed Go files before committing:

```sh
gofmt -w path/to/changed.go
```

Run the [focused native shell checks](docs/development/testing.md#testing-the-sandbox-shell)
from a normal terminal. Do not commit `dist/`, credentials, Session data, target
output, private paths, environment values or generated Seatbelt policy.

## Development rules

### Code

- Add a failing test before changing behavior.
- Keep public parsing in `internal/cli`, common capabilities in
  `internal/commonprofile`, immutable plans in `internal/authority`, and target
  projection/declarative requirements in adapters. The shared executor owns
  backend selection, verification, Sessions, processes and cleanup. Keep typed
  authentication resources separate.
- Preserve stable sanitized errors, process-tree cleanup proof and explicit
  legacy Profile migration. Never delete a Session with possibly live descendants.
- Do not add a backend selector, sandbox bypass, unsandboxed fallback, arbitrary
  shell command option or `$SHELL` lookup.

### Documentation

The [index](docs/README.md) routes readers to a task or contract:

- `guides/` owns user procedures; `reference/` owns schemas and security contracts.
- `development/` owns architecture, testing and maintainer procedures.
- `releases/` holds version-specific notes consumed by publication.
- Fixture explanations stay beside tests; fixture Markdown is deterministic input.

Give each detailed topic one owner and link to it. Keep the README a short
overview: why ACS exists, how it works, installation, a credential-free
quickstart, common commands and the core security boundaries, each linking to
its owning page. Use command help for exhaustive grammar rather than repeating
flags in every guide. Keep security/recovery prerequisites beside
the action they govern, with links to their full contracts.

README tests pin only the security boundaries `There is no unsandboxed
fallback` and `ACS is not an egress firewall`; keep both sentences. Relative
links and `README.md#fragment` links must resolve, so update incoming links when
renaming a README heading. [SECURITY.md](SECURITY.md) owns vulnerability
reporting, supported versions and scope; the
[security model](docs/reference/security-model.md) owns the boundary contract.

Current guides should not track the latest release number. Use stable release
links and reviewed operator-supplied version/digest inputs; preserve exact
versions in compatibility requirements, fixtures and historical records. Do not
add rolling checklists, handoff ledgers or a second changelog. When moving content,
update the index, incoming links and tests. Run example tests when executable
instructions change.

## Pull requests

Before opening a PR:

1. Run formatting, vet, normal/race tests and the focused native shell checks.
2. Inspect `git diff --check` and the complete diff.
3. Use [the PR template](.github/pull_request_template.md) to explain the behavior
   and evidence a reviewer needs; remove unused sections.
4. Confirm that the PR changes no release asset, tag or external state.

PR gates install the candidate bytes on macOS 26 Apple Silicon; the native job
must pass before merge. Portable-source compilation is nonblocking and does not
replace the native Apple Silicon artifact gate.

See [testing and dependency maintenance](docs/development/testing.md) for native,
portable, research and authenticated checks, and
[release preparation](docs/development/releasing.md) for tag authorization,
immutable publication and development-candidate verification.

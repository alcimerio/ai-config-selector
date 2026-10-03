# Synthetic Devin credential fixture provenance

Contributor evidence record for `devin-synthetic-credentials.toml`, not a login
guide or a credential template for users. The fixture is consumed by isolated
acceptance tests; its synthetic values must never be used as real credentials.

## Origin

- Target: Linux Devin 3000.10.21, build `611c1cba`.
- Binary SHA-256: `ba1956450c0e0bf95f477ccd442a0b45b14765402b2377d6737ae758126d70cd`.
- Capture: documented `auth login --force-manual-token-flow` against a disposable
  loopback driver. Devin persisted the file; no fields were invented or rewritten.
- Case: `manual-auth-session-token-user-status-qkmoeck6`.
- Source: `home/data/devin/credentials.toml`.

## Fixture identity

The file is exactly 175 bytes, with SHA-256
`2c8f2a5ad094b05d10c5bf22af343521bb10225c9a9883d818cc0fb6fe814558`.
Its keys are `windsurf_api_key`, `api_server_url`, `devin_webapp_host` and
`devin_api_url`. Bind the saved loopback port in each test. A port collision
must fail rather than cause a fixture rewrite.

## Observation limits

A subsequent isolated `auth status` exited 0 and printed the required
`Logged in` prefix, although local user-info requests received HTTP 501. This
shows stored-state compatibility with that CLI. It does not establish a real
authenticated account or successful backend status. The login UI required
forced teardown, so the capture does not prove normal lifecycle completion.

Native macOS compatibility and public ACS composition remain unverified by this
fixture alone.

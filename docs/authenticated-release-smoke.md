# Optional Authenticated Release Smoke Test

This is a maintainer confidence check, not a release gate. The required release
contract is the credential-free native CI matrix on macOS 26 and Ubuntu 24.04
LTS for darwin/arm64, darwin/amd64, linux/amd64, and linux/arm64.

Run this smoke on the maintainer's macOS 26 Apple Silicon host before the first
release, or when a change affects authentication, the Devin Adapter, Profile
selection, Session isolation, or interactive lifecycle behavior. Do not repeat
it for unrelated releases. Do not provision another host solely for this check.

Only run it with the machine owner's explicit authorization. Never place Devin
credentials in CI, workflow inputs, logs, artifacts, caches, issues, or the
repository. Do not capture terminal output or account details.

## Prepare and install the candidate

Build the candidate from the exact clean source under review, then install it
through the native validator:

```sh
candidate_version=v0.2.0
candidate_directory="$(cd dist/release-candidate && pwd -P)"
install_root="$(mktemp -d)"
install_root="$(cd "$install_root" && pwd -P)"
scripts/validate-promoted-artifact.sh \
  "$candidate_version" "$(go env GOOS)" "$(go env GOARCH)" \
  "$candidate_directory" "$install_root/bin"
candidate_binary="$install_root/bin/acs"
"$candidate_binary" version
```

The version output must match the candidate exactly.

## Exercise the authenticated boundary

First run the repository's opt-in real-Devin integration test:

```sh
ACS_REAL_DEVIN_INTEGRATION=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS \
  go test -tags=integration ./internal/adapter/devin \
  -run '^TestRealDevinPreflightPreservesExactGlobalCatalogAndExistingLogin$' \
  -count=1
```

Then use the installed candidate to create a uniquely named temporary Profile
with at least one global Skill, inspect its dry run, and launch Devin:

```sh
smoke_profile="release-smoke-$(date -u +%Y%m%d%H%M%S)"
"$candidate_binary" devin create-profile --name "$smoke_profile"
"$candidate_binary" devin --profile "$smoke_profile" --dry-run
"$candidate_binary" devin --profile "$smoke_profile"
```

Confirm these outcomes without recording private paths or subprocess output:

1. The visual Profile Builder restores the terminal.
2. The dry run names exactly the selected global Skills and creates no Session.
3. Devin starts with the existing authenticated account.
4. Exactly one leased Session exists while Devin runs.
5. The Session contains only the selected global Skills and the allowlisted
   credential, not unrelated global Devin configuration.
6. A normal Devin exit returns success and removes the leased Session and its
   copied credential.

A failure is useful diagnostic information. Fix or assess it according to the
change's risk; there is no evidence file to attach to the tag or workflow.

## Cleanup

Remove only the uniquely named temporary Profile and installed candidate:

```sh
profile_file="$HOME/.acs/profiles/$smoke_profile.json"
test -f "$profile_file"
rm "$profile_file"
test ! -e "$profile_file"
rm "$candidate_binary"
rmdir "$install_root/bin"
rmdir "$install_root"
```

Do not remove or alter the maintainer's original Devin credential.

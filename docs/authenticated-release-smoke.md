# Authenticated Release-Candidate Smoke Test

This human-owned release gate validates an exact installed ACS candidate on:

- macOS 26 Apple Silicon (`darwin/arm64`);
- a disposable Ubuntu 24.04 amd64 host (`linux/amd64`).

Do not run it without the machine owner's explicit authorization to read the
existing Devin credential and create a temporary Profile. Never put credential
contents, credential or home paths, terminal logs, account details, tokens, or
signed URLs in evidence. Pull-request and `main` automation stays
credential-free.

## Candidate inputs

Use a complete candidate directory produced by the exact source commit under
review. It contains the four archives, `SHA256SUMS`, and the release-specific
`install.sh`:

```sh
candidate_version=v0.2.0
source_commit="$(git rev-parse HEAD)"
candidate_directory="$(cd dist/release-candidate && pwd -P)"
```

Do not rebuild from another checkout. Obtain the target archive digest from its
entry in `SHA256SUMS`. Compute `artifact_set_sha256` as the SHA-256 of the exact
`SHA256SUMS` file; this binds the record to the manifest covering all four
archives. Use `shasum -a 256` on macOS and `sha256sum` on Ubuntu.

Make one private copy of
[`authenticated-evidence.template.json`](authenticated-evidence.template.json)
for each target. Do not commit completed evidence.

## Confirm the reference host

Run `uname -s` and `uname -m`. On macOS, `sw_vers -productVersion` must report
major version 26 and the architecture must be `arm64`. On Ubuntu,
`/etc/os-release` must identify Ubuntu 24.04 and the architecture must be
`x86_64` or `amd64`. Cross-builds and emulators are not host evidence.

Provision a disposable Ubuntu host only after the user authorizes its
infrastructure and cost in that turn. Install Devin through its supported
channel and authenticate interactively, or transfer the minimum credential
through an approved secure channel. Never paste a credential into a command,
log, issue, workflow input, artifact, cache, or repository file.

## Install and identify the candidate

The native validator installs the supplied archive through the supplied
release-specific installer and verifies the complete set first:

```sh
install_root="$(mktemp -d)"
install_root="$(cd "$install_root" && pwd -P)"
scripts/validate-promoted-artifact.sh \
  "$candidate_version" "$(go env GOOS)" "$(go env GOARCH)" \
  "$candidate_directory" "$install_root/bin"
candidate_binary="$install_root/bin/acs"
"$candidate_binary" version
```

The last command must print exactly `acs v0.2.0` for this candidate. Record the
version, 40-character source commit, target archive name, target archive
digest, artifact-set digest, target identity, exact version output, and UTC
start time. Record identifiers only, never local paths.

## Adapter and installed-candidate smoke

The real-Devin contract requires both the integration build tag and this exact
local acknowledgement. Run it only after the account owner authorizes access:

```sh
ACS_REAL_DEVIN_INTEGRATION=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS \
  go test -tags=integration ./internal/adapter/devin \
  -run '^TestRealDevinPreflightPreservesExactGlobalCatalogAndExistingLogin$' \
  -count=1
```

The test uses the public Adapter seam. It creates a synthetic Session, copies
only the allowlisted credential and two fixture Skill Bundles, then asks Devin
to prove the exact global Skill Catalog and usable authentication. Its Session
is temporary. This contract check does not replace the installed-candidate
smoke below.

Create a unique Profile and exercise the installed candidate:

```sh
smoke_profile="release-smoke-$(date -u +%Y%m%d%H%M%S)"
session_baseline="$(mktemp)"
session_after="$(mktemp)"
find "$HOME/.acs/sessions" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sort >"$session_baseline"
"$candidate_binary" devin create-profile --name "$smoke_profile"
"$candidate_binary" devin --profile "$smoke_profile" --dry-run
"$candidate_binary" devin --profile "$smoke_profile"
```

Leave Devin running after the final command. In a second authorized terminal,
identify the single new live Session without recording its path in evidence:

```sh
session_during="$(mktemp)"
session_delta="$(mktemp)"
find "$HOME/.acs/sessions" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sort >"$session_during"
comm -13 "$session_baseline" "$session_during" >"$session_delta"
test "$(wc -l <"$session_delta" | tr -d ' ')" = 1
smoke_session="$(sed -n '1p' "$session_delta")"
test -f "$smoke_session/.active.lock"
test -f "$smoke_session/home/.local/share/devin/credentials.toml"
test ! -e "$smoke_session/home/.config/devin/config.json"
test ! -e "$smoke_session/home/.config/devin/mcp_config.json"
test ! -e "$smoke_session/home/.config/devin/hooks"
```

Compare the Profile's selected `source` and `relativePath` pairs with the
directories under the Session's two managed roots. Those roots must contain
exactly the selected Bundles and no unselected global Bundle:

```text
<smoke_session>/home/.config/devin/skills
<smoke_session>/home/.agents/skills
```

Do not copy either path into evidence. Return to the launch terminal and exit
Devin normally. Then, in the second terminal, verify that the exact leased
Session disappeared and that the pre-existing Session set is unchanged:

```sh
test ! -e "$smoke_session"
find "$HOME/.acs/sessions" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sort >"$session_after"
cmp -s "$session_baseline" "$session_after"
```

Record only boolean outcomes for this checklist:

1. The visual Profile Builder entered its alternate screen and the terminal
   returned to normal input, echo, and display behavior afterward.
2. The temporary Profile was created with at least one selected global Skill.
3. The dry run named the exact selected global Skill Catalog and confirmed that
   it created no Session and started no Devin process.
4. The Profile JSON's `source` and `relativePath` pairs exactly matched the dry
   run. Copy only those pairs into `selected_catalog`, sorted by
   `<source>:<relative_path>`; never record a bundle or host path.
5. The interactive launch started Devin with usable existing authentication.
6. While Devin ran, exactly one new leased Session existed. Its synthetic home
   contained the selected global Skills and allowlisted credential, while
   unrelated global Devin state was absent.
7. Devin exited normally and ACS returned a zero exit status.
8. After exit, the new Session and its copied credential no longer existed.

Do not capture interactive or subprocess output. A failed check remains a
blocking human gate and cannot be represented as passing evidence.

## Cleanup and validate evidence

Remove only the unique Profile and temporary candidate:

```sh
profile_file="$HOME/.acs/profiles/$smoke_profile.json"
test -f "$profile_file"
rm "$profile_file"
test ! -e "$profile_file"
cmp -s "$session_baseline" "$session_after"
rm "$session_baseline" "$session_during" "$session_delta" "$session_after"
rm "$candidate_binary"
rmdir "$install_root/bin"
rmdir "$install_root"
```

Remove any smoke-specific logs. On Ubuntu, remove any copied credential and
destroy the disposable host; both must finish before its evidence can pass. Do
not remove or alter the maintainer's original macOS credential.

Set each completed checklist and cleanup field to `true`, set the UTC completion
time and `result` to `passed`, then validate the private record:

```sh
go run ./tools/authenticatedevidence \
  --evidence "$evidence_file" \
  --version "$candidate_version" \
  --source-commit "$source_commit" \
  --target "$(go env GOOS)/$(go env GOARCH)" \
  --archive-sha256 "$archive_sha256" \
  --artifact-set-sha256 "$artifact_set_sha256"
```

The command must report `status=passed`. A later release workflow supplies its
own expected identity and review window. The validator rejects missing,
malformed, stale, mismatched, incomplete, or extra evidence without echoing
evidence values.

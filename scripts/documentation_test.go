package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV033DocumentationUsesOneSupportAndInstallationContract(t *testing.T) {
	repository := filepath.Clean("..")
	documents := []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/releases/v0.3.3.md",
		"docs/releases/v0.3.3-checklist.md",
	}
	required := []string{
		"macOS 26",
		"Ubuntu 24.04 LTS",
		"darwin/arm64",
		"darwin/amd64",
		"linux/amd64",
		"linux/arm64",
	}

	for _, document := range documents {
		contents, err := os.ReadFile(filepath.Join(repository, document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		text := string(contents)
		for _, term := range required {
			if !strings.Contains(text, term) {
				t.Errorf("%s does not name %s", document, term)
			}
		}
		for _, unsafe := range []string{"curl | sh", "curl|sh", "releases/latest"} {
			if strings.Contains(text, unsafe) {
				t.Errorf("%s presents unsafe or mutable installation text %q", document, unsafe)
			}
		}
	}
}

func TestReadmeTracksPublicLatestReleaseAndV033NativeProcessIsolation(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(contents)

	for _, required := range []string{
		"Skills, while adding fail-closed native process isolation for the supported\nmacOS and Ubuntu targets.",
		"the immutable Release is public, v0.2.0 remains the latest supported release.",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("README.md does not state the current release contract %q", required)
		}
	}
	for _, obsolete := range []string{
		"Skills, while adding downloadable binaries for the supported macOS and Ubuntu\ntargets.",
		"the immutable Release is public, v0.1.0 remains the latest supported release.",
	} {
		if strings.Contains(text, obsolete) {
			t.Errorf("README.md retains obsolete release framing %q", obsolete)
		}
	}
	if occurrences := strings.Count(text, "v0.2.0"); occurrences != 1 {
		t.Errorf("README.md v0.2.0 references = %d, want 1 public latest-release reference", occurrences)
	}
}

func TestV033ReleaseNotesMatchTagWorkflowPath(t *testing.T) {
	notes := filepath.Join("..", "docs", "releases", "v0.3.3.md")
	info, err := os.Stat(notes)
	if err != nil {
		t.Fatalf("stat release notes: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("v0.3.3 release notes are empty")
	}

	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	if !strings.Contains(string(workflow), `"docs/releases/$GITHUB_REF_NAME.md"`) {
		t.Fatal("release workflow no longer consumes version-controlled tag notes")
	}
}

func TestV033ReleaseUsesSoloMaintainerAuthorizationBoundary(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	text := string(workflow)
	for _, required := range []string{
		"environment: release",
		"permission-administration: write",
		"GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
		"ACS_RELEASE_ACTOR_ID: ${{ github.actor_id }}",
		"Verify the authorized human actor before credentials",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release workflow is missing solo-maintainer boundary %q", required)
		}
	}
	for _, obsolete := range []string{
		"ACS_RELEASE_PUBLISH_APP_CLIENT_ID",
		"ACS_RELEASE_PUBLISH_APP_PRIVATE_KEY",
		"id: release-token",
	} {
		if strings.Contains(text, obsolete) {
			t.Errorf("release workflow still requires obsolete publication App configuration %q", obsolete)
		}
	}

	contributors, err := os.ReadFile(filepath.Join("..", "CONTRIBUTING.md"))
	if err != nil {
		t.Fatalf("read CONTRIBUTING.md: %v", err)
	}
	for _, required := range []string{
		"scripts/prepare-release-tag.sh v0.3.3",
		"git push origin refs/tags/v0.3.3",
		"with no\nrequired reviewers",
	} {
		if !strings.Contains(string(contributors), required) {
			t.Errorf("CONTRIBUTING.md is missing solo-maintainer release guidance %q", required)
		}
	}
	for _, document := range []string{
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/authenticated-release-smoke.md",
		"docs/releases/v0.3.3-checklist.md",
		".github/workflows/release.yml",
	} {
		contents, err := os.ReadFile(filepath.Join("..", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		for _, obsolete := range []string{
			"authenticated-evidence.template.json",
			"tools/authenticatedevidence",
			"tools/releasegate",
			"evidence-set.json",
		} {
			if strings.Contains(string(contents), obsolete) {
				t.Errorf("%s still requires obsolete release evidence %q", document, obsolete)
			}
		}
	}
}

func TestV033DefaultInstallVerificationDoesNotAssumePATH(t *testing.T) {
	for _, document := range []string{"README.md", "docs/releases/v0.3.3.md"} {
		contents, err := os.ReadFile(filepath.Join("..", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		if !strings.Contains(string(contents), `"$HOME/.local/bin/acs" version`) {
			t.Errorf("%s does not verify the default installed binary by exact path", document)
		}
	}
}

func TestV033ReadmeArchiveVerificationUsesExactV033Asset(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	const releaseVersion = "v0.3.3"
	wantArchive := "acs_" + strings.TrimPrefix(releaseVersion, "v") + "_darwin_arm64.tar.gz"
	text := string(contents)
	for _, required := range []string{
		"release_version=" + releaseVersion,
		"archive=" + wantArchive,
		`"$release_url/$archive"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("README.md archive verification does not bind %s to %q", releaseVersion, required)
		}
	}
	if strings.Contains(text, "acs_0.2.0_darwin_arm64.tar.gz") {
		t.Fatal("README.md archive verification retains the v0.2.0 darwin/arm64 asset")
	}
	if strings.Contains(text, "acs_0.3.0_darwin_arm64.tar.gz") {
		t.Fatal("README.md archive verification retains the unpublished v0.3.0 darwin/arm64 asset")
	}
	if strings.Contains(text, "acs_0.3.1_darwin_arm64.tar.gz") {
		t.Fatal("README.md archive verification retains the unpublished v0.3.1 darwin/arm64 asset")
	}
	if strings.Contains(text, "acs_0.3.2_darwin_arm64.tar.gz") {
		t.Fatal("README.md archive verification retains the unpublished v0.3.2 darwin/arm64 asset")
	}
}

func TestV033ChecklistSeparatesTagAuthorizationFromPostTagEvidence(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "docs", "releases", "v0.3.3-checklist.md"))
	if err != nil {
		t.Fatalf("read v0.3.3 checklist: %v", err)
	}
	text := string(contents)
	normalizedText := strings.Join(strings.Fields(text), " ")
	preTag := "## Pre-tag authorization evidence — blocks tag creation and push"
	localTag := "## Local tag preparation and push authorization — blocks push only"
	tagTriggered := "## Tag-triggered workflow evidence — necessarily pending before push"
	postPublication := "## Public-release evidence — necessarily pending until publication"
	followUp := "## Auditable post-publication follow-up branch and PR"
	for _, required := range []string{
		preTag,
		localTag,
		tagTriggered,
		postPublication,
		followUp,
		"Pre-tag review of [issue #62]",
		"docs/v0.3.3-publication-evidence",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("v0.3.3 checklist omits non-circular release evidence guard %q", required)
		}
	}
	for _, required := range []string{
		"does not complete any v0.3.3 tag-run row",
		"do not block local tag creation or the authorized tag push",
		"public workflow/job URLs, target outcomes, public asset hashes, provenance results, and immutable Release identity",
		"policy-App client configuration, and release-environment private-key secret presence",
	} {
		if !strings.Contains(normalizedText, required) {
			t.Errorf("v0.3.3 checklist omits non-circular release evidence guard %q", required)
		}
	}
	if !(strings.Index(text, preTag) < strings.Index(text, localTag) &&
		strings.Index(text, localTag) < strings.Index(text, tagTriggered) &&
		strings.Index(text, tagTriggered) < strings.Index(text, postPublication) &&
		strings.Index(text, postPublication) < strings.Index(text, followUp)) {
		t.Fatal("v0.3.3 checklist does not order pre-tag, tag-triggered, publication, and follow-up evidence")
	}
}

func TestV033ChecklistPreservesUnpublishedPriorTagRecords(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "docs", "releases", "v0.3.3-checklist.md"))
	if err != nil {
		t.Fatalf("read v0.3.3 checklist: %v", err)
	}
	text := string(contents)
	normalizedText := strings.Join(strings.Fields(text), " ")
	for _, required := range []string{
		"[v0.3.0 checklist](v0.3.0-checklist.md)",
		"[v0.3.1 checklist](v0.3.1-checklist.md)",
		"[v0.3.2 checklist](v0.3.2-checklist.md)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("v0.3.3 checklist does not preserve the unpublished prior tag records %q", required)
		}
	}
	if !strings.Contains(normalizedText, "never moved, deleted, or reused") {
		t.Error("v0.3.3 checklist does not preserve the prior immutable tags")
	}
	if !strings.Contains(normalizedText, "immutable-publication policy withheld all three Releases") {
		t.Error("v0.3.3 checklist does not state that all three prior candidates were withheld")
	}
}

func TestHistoricalReleaseRecordsRemainAvailable(t *testing.T) {
	for _, document := range []string{
		"docs/releases/v0.2.0.md",
		"docs/releases/v0.2.0-checklist.md",
		"docs/releases/v0.3.0.md",
		"docs/releases/v0.3.0-checklist.md",
		"docs/releases/v0.3.1.md",
		"docs/releases/v0.3.1-checklist.md",
		"docs/releases/v0.3.2.md",
		"docs/releases/v0.3.2-checklist.md",
	} {
		contents, err := os.ReadFile(filepath.Join("..", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		if len(contents) == 0 {
			t.Errorf("historical release record %s is empty", document)
		}
	}
}

func TestLinuxWorkflowsUseTheCompleteDocumentedCancelreaderException(t *testing.T) {
	want := `go test -race ./... -skip '^TestProfileBuilderPTYRestoresTerminal/(runtime_error|recovered_panic)$'`
	ci, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	if !strings.Contains(string(ci), want) {
		t.Error("ci.yml does not use the complete Linux cancelreader exception")
	}

	for _, workflow := range []string{"promoted-artifacts.yml", "release.yml"} {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow))
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		text := string(contents)
		for _, required := range []string{
			`if [[ "${{ matrix.os }}" == "linux" ]]; then`,
			want,
			"else\n            go test -race ./...\n          fi",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing the platform-specific race gate %q", workflow, required)
			}
		}
	}
}

func TestContributingDocumentsDarwinSeatbeltRaceExceptionWithoutNumericClaim(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "CONTRIBUTING.md"))
	if err != nil {
		t.Fatalf("read CONTRIBUTING.md: %v", err)
	}
	text := string(contents)
	normalizedText := strings.ToLower(strings.Join(strings.Fields(text), " "))

	if strings.Contains(text, "skip only the three Darwin tests") {
		t.Fatal("CONTRIBUTING.md contains the inaccurate numeric Darwin Seatbelt race-test claim")
	}

	const required = "only darwin tests that require nested execution of the race-instrumented test binary inside the production seatbelt policy are skipped"
	if !strings.Contains(normalizedText, required) {
		t.Errorf("CONTRIBUTING.md must explain the Darwin Seatbelt race-test exception: %q", required)
	}
}

func TestPromotedArtifactGateDeclaresExpectedSandboxCapability(t *testing.T) {
	for _, workflow := range []string{"promoted-artifacts.yml", "release.yml"} {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow))
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		text := string(contents)
		if got := strings.Count(text, "sandbox_backend: available"); got != 4 {
			t.Errorf("%s declares available sandbox capability %d times, want 4", workflow, got)
		}
		if got := strings.Count(text, "sandbox_backend: unavailable"); got != 0 {
			t.Errorf("%s declares unavailable sandbox capability %d times, want 0", workflow, got)
		}
		for _, required := range []string{
			"target: darwin/arm64\n            runner: macos-26\n            os: darwin\n            arch: arm64\n            sandbox_backend: available",
			"target: darwin/amd64\n            runner: macos-26-intel\n            os: darwin\n            arch: amd64\n            sandbox_backend: available",
			"target: linux/amd64\n            runner: ubuntu-24.04\n            os: linux\n            arch: amd64\n            sandbox_backend: available",
			"target: linux/arm64\n            runner: ubuntu-24.04-arm\n            os: linux\n            arch: arm64\n            sandbox_backend: available",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing the expected native capability row %q", workflow, required)
			}
		}
		if !strings.Contains(text, "ACS_PROMOTED_SANDBOX_BACKEND: ${{ matrix.sandbox_backend }}") {
			t.Errorf("%s does not pass the target sandbox capability to installed-artifact acceptance", workflow)
		}
		normalSuite := strings.Index(text, "run: go test ./...")
		raceSuite := strings.Index(text, "go test -race ./...")
		promotedAcceptance := strings.Index(text, "go test ./acceptance -count=1")
		if normalSuite < 0 || raceSuite < normalSuite || promotedAcceptance < raceSuite {
			t.Errorf("%s does not preserve normal native, race, and promoted-artifact acceptance order", workflow)
		}
	}

	acceptance, err := os.ReadFile(filepath.Join("..", "acceptance", "promoted_artifact_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(acceptance)
	for _, preserved := range []string{
		"assertPromotedArtifactDryRunAndFakeDevinLaunchPreserveTheRuntimeBoundary",
		"assertPromotedArtifactForwardsSignalsAndPreservesConcurrentSessionLeases",
	} {
		if !strings.Contains(text, preserved) {
			t.Errorf("installed-artifact acceptance no longer preserves %s", preserved)
		}
	}
}

func TestNativeCandidateGateKeepsFourTargetEvidenceSanitizedAndImmutable(t *testing.T) {
	for _, workflow := range []string{"promoted-artifacts.yml", "release.yml"} {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow))
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		text := string(contents)
		for _, required := range []string{
			"Download immutable candidate artifact set",
			"Restore installer mode normalized by artifact transport",
			"Verify host and install supplied candidate",
			"Exercise installed candidate as a black box",
			"Record sanitized native candidate observation",
			"The candidate itself is never rebuilt in this job.",
			"No credentials, account data, target output, Session contents, private paths, generated policy, environment values, or control characters are recorded.",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing native-candidate evidence guard %q", workflow, required)
			}
		}
	}

	release, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(release)
	native := strings.Index(text, "  native:\n")
	attest := strings.Index(text, "  attest:\n")
	publish := strings.Index(text, "  publish:\n")
	if native < 0 || attest < native || publish < attest ||
		!strings.Contains(text[attest:publish], "- native") || !strings.Contains(text[publish:], "- native") || !strings.Contains(text[publish:], "- attest") {
		t.Fatal("attestation and publication do not depend on the completed four-target native gate")
	}

	acceptance, err := os.ReadFile(filepath.Join("..", "acceptance", "promoted_artifact_native_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"TestPromotedArtifactNativeContainmentContract",
		"filesystem environment descriptors sockets IP preflight and descendants",
		"assertPromotedArtifactNativePreflightFailureIsSafe",
		"assertPromotedArtifactMissingBackendFailsClosed",
		"missing backend OR invalid policy cannot start a marker",
		"missing required backend started a target marker",
		"assertNoSessions(t, home)",
		"assertSafeCandidateFailure",
		"DescendantStarted",
		"HostSocketReachable",
		"DescriptorLeaked",
		"ExternalWriteSucceeded",
		"assertDescendantStopsAfterCandidateReturn",
	} {
		if !strings.Contains(string(acceptance), required) {
			t.Errorf("native installed-candidate acceptance is missing %q", required)
		}
	}

	for _, document := range []string{"README.md", "CONTRIBUTING.md", "docs/architecture.md", "docs/authenticated-release-smoke.md"} {
		contents, err := os.ReadFile(filepath.Join("..", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		for _, required := range []string{
			"native candidate gate",
			"darwin/arm64",
			"darwin/amd64",
			"linux/amd64",
			"linux/arm64",
		} {
			if !strings.Contains(strings.ToLower(string(contents)), strings.ToLower(required)) {
				t.Errorf("%s does not document native-candidate evidence %q", document, required)
			}
		}
	}
}

func TestReleaseRerunsReuseTheCandidateJobsExactArtifactName(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"artifact-name: ${{ steps.artifact-name.outputs.name }}",
		"id: artifact-name",
		"name: ${{ steps.artifact-name.outputs.name }}",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release candidate job does not publish its exact artifact name through %q", required)
		}
	}
	if got := strings.Count(text, "name: ${{ needs.candidate.outputs.artifact-name }}"); got != 3 {
		t.Fatalf("release has %d candidate artifact consumers using the producer output, want 3", got)
	}
	if got := strings.Count(text, "name: release-candidate-${{ github.run_id }}-${{ github.run_attempt }}"); got != 0 {
		t.Fatalf("release has %d jobs independently recomputing an attempt-scoped artifact name", got)
	}
}

func TestAuthenticatedReleaseSmokeRetainsRiskAndSafetyContract(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "docs", "authenticated-release-smoke.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"sandbox policy",
		"ACS_REAL_DEVIN_INTEGRATION=I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS",
		"Do not capture terminal output or account details.",
		"supplemental to that native candidate gate",
		"never waives, replaces, or weakens",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("authenticated release smoke omits %q", required)
		}
	}
}

func TestGeneralCIUsesTheCertifiedUbuntuRelease(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if strings.Count(text, "runs-on: ubuntu-24.04") != 1 {
		t.Fatal("general CI must run on exactly one certified Ubuntu 24.04 runner")
	}
	if strings.Contains(text, "runs-on: ubuntu-latest") {
		t.Fatal("general CI must not allow its Ubuntu release to drift")
	}
}

func TestWorkflowsRunningNativeTestsProvisionTrustedUbuntuBubblewrap(t *testing.T) {
	workflows := []struct {
		name              string
		platformGuard     string
		architectureCheck string
	}{
		{name: "ci.yml", architectureCheck: `$'ii \nbubblewrap\nbubblewrap\namd64'`},
		{
			name:              "promoted-artifacts.yml",
			platformGuard:     `if: matrix.os == 'linux'`,
			architectureCheck: `$'ii \nbubblewrap\nbubblewrap\n'"${{ matrix.arch }}"`,
		},
		{
			name:              "release.yml",
			platformGuard:     `if: matrix.os == 'linux'`,
			architectureCheck: `$'ii \nbubblewrap\nbubblewrap\n'"${{ matrix.arch }}"`,
		},
	}

	for _, workflow := range workflows {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow.name))
		if err != nil {
			t.Fatalf("read %s: %v", workflow.name, err)
		}
		text := string(contents)
		for _, setup := range []string{
			"Acquire::Retries=2",
			"Acquire::http::Timeout=15",
			"Acquire::https::Timeout=15",
			`case "$(/usr/bin/dpkg --print-architecture)" in`,
			"amd64) ubuntu_archive='https://archive.ubuntu.com/ubuntu/' ;;",
			"arm64) ubuntu_archive='https://ports.ubuntu.com/ubuntu-ports/' ;;",
			"*) echo 'Unsupported Ubuntu package architecture' >&2; exit 1 ;;",
			"https://archive.ubuntu.com/ubuntu/",
			"timeout 60s sudo apt-get \"${apt_options[@]}\" install --yes --no-install-recommends apparmor apparmor-utils bubblewrap",
			"--retry 3 --retry-all-errors --connect-timeout 10 --max-time 60",
			"https://gitlab.com/apparmor/apparmor/-/raw/v4.0.3/profiles/apparmor/profiles/extras/bwrap-userns-restrict",
			"a964037f6cf0df1099f14226b037eaedde6237c86e715188e93eb460b30be859",
			"sha256sum --check --status",
			"sudo install --owner=root --group=root --mode=0644 \"$profile_source\" /etc/apparmor.d/bwrap-userns-restrict",
			"sudo /usr/sbin/apparmor_parser --replace /etc/apparmor.d/bwrap-userns-restrict",
			"sudo /usr/sbin/aa-status --enabled",
			`[[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap && -x /usr/bin/bwrap ]]`,
			`stat --format='%u:%a' /usr/bin/bwrap`,
			`/usr/bin/dpkg-query --search /usr/bin/bwrap`,
			`/usr/bin/dpkg --verify --verify-format=rpm bubblewrap`,
			"--unshare-user --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup",
			"--symlink usr/bin /bin",
			"--symlink usr/sbin /sbin",
			"--symlink usr/lib /lib",
			"--symlink usr/lib64 /lib64",
			workflow.architectureCheck,
		} {
			if got := strings.Count(text, setup); got != 1 {
				t.Errorf("%s contains Ubuntu Bubblewrap setup %q %d times, want 1", workflow.name, setup, got)
			}
		}
		if got := strings.Count(text, "timeout 60s sudo apt-get \"${apt_options[@]}\" update"); got != 2 {
			t.Errorf("%s contains %d bounded Ubuntu package index attempts, want 2", workflow.name, got)
		}
		for _, unsafe := range []string{
			"kernel.apparmor_restrict_unprivileged_userns=0",
			"apparmor_parser -R",
			"/etc/apparmor.d/disable",
		} {
			if strings.Contains(text, unsafe) {
				t.Errorf("%s weakens AppArmor with %q", workflow.name, unsafe)
			}
		}
		if workflow.platformGuard != "" && strings.Count(text, workflow.platformGuard) != 1 {
			t.Errorf("%s does not restrict Ubuntu Bubblewrap setup to its Linux matrix entries", workflow.name)
		}
		if strings.Index(text, "install --yes --no-install-recommends apparmor apparmor-utils bubblewrap") > strings.Index(text, "go test ./...") {
			t.Errorf("%s installs Bubblewrap after native tests", workflow.name)
		}
		if strings.Index(text, "--unshare-user --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup") < strings.Index(text, "/usr/sbin/apparmor_parser --replace") {
			t.Errorf("%s probes Bubblewrap before provisioning the AppArmor profile", workflow.name)
		}
	}
}

func TestWorkflowsUseEquivalentBubblewrapCapabilityProbe(t *testing.T) {
	workflows := []string{"ci.yml", "promoted-artifacts.yml", "release.yml"}
	var want string
	for _, name := range workflows {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		probe := bubblewrapCapabilityProbeBlock(t, string(contents))
		if want == "" {
			want = probe
			continue
		}
		if probe != want {
			t.Errorf("%s Bubblewrap capability probe differs:\n%s\nwant:\n%s", name, probe, want)
		}
	}
}

func bubblewrapCapabilityProbeBlock(t *testing.T, workflow string) string {
	t.Helper()
	const start = "          /usr/bin/bwrap \\\n"
	const end = "            --setenv PATH /usr/bin:/bin --chdir /tmp -- /usr/bin/true"
	first := strings.Index(workflow, start)
	if first == -1 {
		t.Fatal("workflow does not contain a Bubblewrap capability probe")
	}
	last := strings.Index(workflow[first:], end)
	if last == -1 {
		t.Fatal("workflow does not contain the Bubblewrap capability probe target")
	}
	return workflow[first : first+last+len(end)]
}

func TestReadmeDescribesCurrentPlatformSandboxCapabilities(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := strings.Join(strings.Fields(string(contents)), " ")
	for _, required := range []string{
		"Seatbelt-contained interactive launches on macOS 26",
		"On macOS 26, this command runs every Devin preflight, interactive process, and descendant inside Seatbelt",
		"`/usr/bin/sandbox-exec`",
		"Ubuntu 24.04",
		"`/usr/bin/bwrap`",
		"signed Ubuntu `bubblewrap` package",
		"package database and packaged checksums are controlled by root",
		"outbound IP networking",
		"host Unix sockets",
		"There is no unsandboxed fallback on either platform",
		"ACS removes a leased Session after launch setup fails, or only after the sandboxed process tree has exited or been terminated and containment is settled",
		"That contained Session lifecycle is available through Seatbelt on macOS and Bubblewrap on Ubuntu",
		"`policy_rejected`: the generated native policy was rejected before Devin",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("README.md does not explain the sandbox launch state with %q", required)
		}
	}
	for _, obsolete := range []string{
		"current sandbox increment is fail-closed",
		"Seatbelt backend in #57",
		"Bubblewrap backend in #64",
		"After the native backend for the host lands",
		"That Session lifecycle is not currently available",
		"macOS launches remain unavailable",
	} {
		if strings.Contains(text, obsolete) {
			t.Errorf("README.md retains obsolete all-platform fail-closed text %q", obsolete)
		}
	}
}

func TestDocumentationDescribesTargetedAppArmorRemediation(t *testing.T) {
	contributors, err := os.ReadFile(filepath.Join("..", "CONTRIBUTING.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Ubuntu native-test remediation",
		"`bwrap-userns-restrict` profile for `/usr/bin/bwrap`",
		"Ubuntu Noble exposes this optional profile through\n`apparmor-profiles`",
		"not enabled by default",
		"documented\ncompatibility may lag upstream",
		"AppArmor project v4.0.3",
		"a964037f6cf0df1099f14226b037eaedde6237c86e715188e93eb460b30be859",
		"real `/usr/bin/bwrap` user-namespace\nprobe",
		"does not\nset `kernel.apparmor_restrict_unprivileged_userns=0`",
		"skip\nnative tests",
		"runtime capability checks",
	} {
		if !strings.Contains(string(contributors), required) {
			t.Errorf("CONTRIBUTING.md is missing AppArmor remediation detail %q", required)
		}
	}
	if strings.Contains(string(contributors), "apparmor-profiles-extra") {
		t.Fatal("CONTRIBUTING.md names the wrong Ubuntu Noble profile package")
	}

	readme, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"host AppArmor policy blocks unprivileged user namespaces",
		"does not disable the global AppArmor restriction or run without\ncontainment",
	} {
		if !strings.Contains(string(readme), required) {
			t.Errorf("README.md is missing AppArmor remediation detail %q", required)
		}
	}

	architecture, err := os.ReadFile(filepath.Join("..", "docs", "architecture.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"pinned,\nSHA-256-verified AppArmor upstream release",
		"preserves Ubuntu's global unprivileged-user-namespace\nrestriction",
	} {
		if !strings.Contains(string(architecture), required) {
			t.Errorf("docs/architecture.md is missing AppArmor remediation detail %q", required)
		}
	}
}

func TestContributorRaceGateDocumentsNarrowNativeExceptions(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "CONTRIBUTING.md"))
	if err != nil {
		t.Fatalf("read CONTRIBUTING.md: %v", err)
	}
	text := string(contents)
	for _, want := range []string{
		`if [ "$(go env GOOS)" = linux ]; then`,
		`go test -race ./... -skip '^TestProfileBuilderPTYRestoresTerminal/(runtime_error|recovered_panic)$'`,
		"else\n  go test -race ./...\nfi",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("CONTRIBUTING.md is missing the platform-specific race gate %q", want)
		}
	}
	normalized := strings.Join(strings.Fields(text), " ")
	for _, want := range []string{
		"ThreadSanitizer runtime cannot start inside the production Seatbelt policy",
		"Only Darwin tests that require nested execution of the race-instrumented test binary inside the production Seatbelt policy are skipped",
		"preceding non-race native suite and the installed promoted-artifact acceptance",
	} {
		if !strings.Contains(normalized, want) {
			t.Errorf("CONTRIBUTING.md is missing the macOS race rationale %q", want)
		}
	}
}

func TestV033DocumentationBindsProtectionClaimsToNativeEvidence(t *testing.T) {
	repository := filepath.Clean("..")
	documents := []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/releases/v0.3.3.md",
		"docs/releases/v0.3.3-checklist.md",
	}
	required := []string{
		"https://github.com/alcimerio/ai-config-selector/issues/62",
		"acceptance/promoted_artifact_native_test.go",
		"acceptance/promoted_artifact_test.go",
		".github/workflows/release.yml",
		"darwin/arm64",
		"darwin/amd64",
		"linux/amd64",
		"linux/arm64",
	}

	for _, document := range documents {
		contents, err := os.ReadFile(filepath.Join(repository, document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		text := string(contents)
		for _, want := range required {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not bind its protection contract to %q", document, want)
			}
		}
	}

	for _, document := range []string{"CONTRIBUTING.md", "docs/architecture.md", "docs/authenticated-release-smoke.md"} {
		contents, err := os.ReadFile(filepath.Join(repository, document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		if strings.Contains(string(contents), "v0.2.0") {
			t.Errorf("current release document %s retains stale v0.2.0 wording", document)
		}
		if strings.Contains(string(contents), "v0.3.0") {
			t.Errorf("current release document %s retains stale unpublished v0.3.0 wording", document)
		}
		if strings.Contains(string(contents), "v0.3.1") {
			t.Errorf("current release document %s retains stale unpublished v0.3.1 wording", document)
		}
		if strings.Contains(string(contents), "v0.3.2") {
			t.Errorf("current release document %s retains stale unpublished v0.3.2 wording", document)
		}
	}

	smoke, err := os.ReadFile(filepath.Join(repository, "docs", "authenticated-release-smoke.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(smoke), "candidate_version=v0.3.3") {
		t.Error("authenticated release smoke does not select the v0.3.3 candidate")
	}

	readme, err := os.ReadFile(filepath.Join(repository, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, exception := range []string{
		"ACS is not an egress firewall",
		"There is no unsandboxed fallback",
		"compromised administrator",
		"Source builds and the optional authenticated smoke",
	} {
		if !strings.Contains(string(readme), exception) {
			t.Errorf("README.md does not retain limitation record %q", exception)
		}
	}
}

func TestDevelopmentWorkflowsBuildTheV033Candidate(t *testing.T) {
	for _, workflow := range []string{"ci.yml", "macos.yml", "promoted-artifacts.yml"} {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow))
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		if !strings.Contains(string(contents), "v0.3.3") {
			t.Errorf("%s does not build the v0.3.3 candidate", workflow)
		}
		if strings.Contains(string(contents), "v0.3.0") {
			t.Errorf("%s retains stale unpublished v0.3.0 candidate validation", workflow)
		}
		if strings.Contains(string(contents), "v0.3.1") {
			t.Errorf("%s retains stale unpublished v0.3.1 candidate validation", workflow)
		}
		if strings.Contains(string(contents), "v0.3.2") {
			t.Errorf("%s retains stale unpublished v0.3.2 candidate validation", workflow)
		}
		if strings.Contains(string(contents), "v0.2.0") {
			t.Errorf("%s retains stale v0.2.0 candidate validation", workflow)
		}
	}
}

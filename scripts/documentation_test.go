package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentDocumentationDefinesTheMacOSSandboxShellContract(t *testing.T) {
	repository := ".."
	for _, document := range []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/development/architecture.md",
		"docs/guides/manual-upgrade-recovery.md",
	} {
		contents := readRepositoryFile(t, repository, document)
		if len(strings.TrimSpace(contents)) == 0 {
			t.Errorf("current document %s is empty", document)
		}
	}

	// The README is free-form prose. Only the two security boundaries a reader
	// must never lose are pinned; wording elsewhere is not a test contract.
	readme := readRepositoryFile(t, repository, "README.md")
	for _, required := range []string{
		"There is no unsandboxed fallback",
		"ACS is not an egress firewall",
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README.md omits security boundary %q", required)
		}
	}
	for _, stale := range []string{
		"ACS supports Darwin and Linux",
		"supported macOS and Ubuntu targets",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("README.md retains stale support claim %q", stale)
		}
	}

	contributing := readRepositoryFile(t, repository, "CONTRIBUTING.md")
	for _, required := range []string{"Apple Silicon (`darwin/arm64`)", "native Apple Silicon artifact gate"} {
		if !strings.Contains(contributing, required) {
			t.Errorf("CONTRIBUTING.md omits current contract %q", required)
		}
	}
	for _, stale := range []string{"macOS 26 arm64 and Intel", "acs_0.4.0_darwin_amd64.tar.gz", "both macOS targets", "two native artifact gates"} {
		if strings.Contains(contributing, stale) {
			t.Errorf("CONTRIBUTING.md retains stale current guidance %q", stale)
		}
	}
}

func TestReleaseArtifactContractKeepsLinuxCandidatesSeparate(t *testing.T) {
	repository := ".."
	sharedGates := readRepositoryFile(t, repository, filepath.Join("scripts", "run-native-candidate-gates.sh"))
	for _, workflow := range []string{"promoted-artifacts.yml", "release.yml"} {
		text := readRepositoryFile(t, repository, filepath.Join(".github", "workflows", workflow))
		for _, row := range []string{
			"target: darwin/arm64\n            runner: macos-26\n            os: darwin\n            arch: arm64\n            sandbox_backend: available",
		} {
			if !strings.Contains(text, row) {
				t.Errorf("%s omits native row %q", workflow, row)
			}
		}
		if strings.Count(text, "sandbox_backend: available") != 2 || strings.Count(text, "target: darwin/arm64") != 2 {
			t.Errorf("%s must declare two reviewed version rows for the same native target", workflow)
		}
		for _, forbidden := range []string{"target: darwin/amd64", "macos-26-intel", "target: linux/", "ubuntu-24.04-arm", "Install and verify Ubuntu Bubblewrap", "bwrap-userns-restrict"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s retains Linux release-gate content %q", workflow, forbidden)
			}
		}
		for _, required := range []string{
			"scripts/run-native-candidate-gates.sh",
			"go test -race ./...",
			"The candidate itself is never rebuilt in this job.",
			"No credentials, account data, target output, Session contents, private paths, generated policy, environment values, or control characters are recorded.",
		} {
			if !strings.Contains(text, required) && !strings.Contains(sharedGates, required) {
				t.Errorf("%s omits release guard %q", workflow, required)
			}
		}
	}

	goreleaser := readRepositoryFile(t, repository, ".goreleaser.yaml")
	for _, required := range []string{
		"      - darwin", "      - linux", "      - arm64", "      - amd64", "CGO_ENABLED=0",
		"      - goos: darwin\n        goarch: amd64", "      - goos: linux\n        goarch: arm64",
		"release:\n  disable: true",
	} {
		if !strings.Contains(goreleaser, required) {
			t.Errorf("GoReleaser omits candidate boundary %q", required)
		}
	}
	candidate := readRepositoryFile(t, repository, filepath.Join("scripts", "release-candidate.sh"))
	if !strings.Contains(candidate, `artifact="acs_${archive_version}_${target}.tar.gz"`) {
		t.Error("release candidate script does not stage the selected target archive")
	}
	if strings.Contains(candidate, "darwin_amd64.tar.gz") {
		t.Fatal("release candidate script still stages an Intel archive")
	}
	for _, required := range []string{"darwin_arm64 linux_amd64", "candidate_directory=\"dist/linux-candidate\"", "--linux-candidate"} {
		if !strings.Contains(candidate, required) {
			t.Errorf("candidate script omits separate Linux staging %q", required)
		}
	}
	installer := readRepositoryFile(t, repository, filepath.Join("scripts", "install.sh.tmpl"))
	if !strings.Contains(installer, `[ -n "$candidate_directory" ] || fail "ACS release installers support macOS only`) || !strings.Contains(installer, "--candidate-dir)") {
		t.Fatal("installer does not reject unsupported Linux hosts clearly")
	}
	publication := readRepositoryFile(t, repository, "internal/release/publication/plan.go")
	if strings.Contains(publication, "linux_") {
		t.Fatal("publication permits Linux assets")
	}
	linuxWorkflow := readRepositoryFile(t, repository, ".github/workflows/linux-candidate.yml")
	for _, required := range []string{"runs-on: ubuntu-24.04", "scripts/check-go-vulnerabilities.sh binary", "--linux-candidate", "dist/linux-candidate/*.tar.gz", "dist/linux-candidate/SHA256SUMS", "github.event_name != 'pull_request'"} {
		if !strings.Contains(linuxWorkflow, required) {
			t.Errorf("Linux candidate workflow omits %q", required)
		}
	}
	for _, forbidden := range []string{"publish-release", "go build", "release-candidate.sh", "contents: write"} {
		if strings.Contains(linuxWorkflow, forbidden) {
			t.Errorf("Linux candidate workflow contains %q", forbidden)
		}
	}
}

func TestDevelopmentCandidateVersionHasReleaseNotes(t *testing.T) {
	repository := ".."
	promoted := readRepositoryFile(t, repository, filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	macos := readRepositoryFile(t, repository, filepath.Join(".github", "workflows", "macos.yml"))
	if !strings.Contains(promoted, "ACS_CANDIDATE_VERSION: v0.5.1") {
		t.Fatal("promoted workflow does not use the v0.5.1 development identity")
	}
	if !strings.Contains(macos, "scripts/release-candidate.sh v0.5.1") {
		t.Fatal("macOS workflow does not verify the v0.5.1 candidate")
	}
	for _, stale := range []string{
		"ACS_CANDIDATE_VERSION: v0.4.0",
		"ACS_CANDIDATE_VERSION: v0.5.0",
		"scripts/release-candidate.sh v0.4.0",
		"scripts/release-candidate.sh v0.5.0",
	} {
		if strings.Contains(promoted, stale) || strings.Contains(macos, stale) {
			t.Fatalf("development workflow retains stale candidate identity %q", stale)
		}
	}

	notes := readRepositoryFile(t, repository, filepath.Join("docs", "releases", "v0.5.1.md"))
	if !strings.HasPrefix(notes, "# ACS v0.5.1\n") {
		t.Fatal("current candidate release notes have the wrong version")
	}
	for _, script := range []string{"prepare-release-tag.sh", "release-tag-identity.sh"} {
		contents := readRepositoryFile(t, repository, filepath.Join("scripts", script))
		if !strings.Contains(contents, `release_notes="docs/releases/$release_tag.md"`) {
			t.Errorf("%s no longer validates version-controlled release notes", script)
		}
	}
}

func TestPortableLinuxTestsDoNotClaimRuntimeSupport(t *testing.T) {
	ci := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "ci.yml"))
	for _, required := range []string{
		"Portable Linux tests (ubuntu-24.04)",
		"runs-on: ubuntu-24.04",
		"CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go vet ./...",
		"CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build",
		"CGO_ENABLED=0 go test ./...",
		"Linux launch fails closed without a backend",
		"Linux sandbox backend is not available yet",
	} {
		if !strings.Contains(ci, required) {
			t.Errorf("Portable Linux job omits %q", required)
		}
	}
	// Portable tests are not native containment evidence: no Linux sandbox
	// backend, release candidate, or skipped-failure escape hatch belongs here.
	for _, forbidden := range []string{"continue-on-error", "Bubblewrap", "bwrap", "release-candidate.sh"} {
		if strings.Contains(ci, forbidden) {
			t.Errorf("Portable Linux job must not contain %q", forbidden)
		}
	}
}

func TestImmutableReleaseSafetyStillDependsOnNativeAppleSiliconAndAttestation(t *testing.T) {
	release := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "release.yml"))
	for _, required := range []string{
		"tags:\n      - \"v*\"",
		"cancel-in-progress: false",
		"Validate annotated tag identity and release notes",
		"Build the candidate exactly once",
		"Attest exact release bytes",
		"Stage and publish immutable Release",
		"environment: release",
		"scripts/publish-release.sh",
	} {
		if !strings.Contains(release, required) {
			t.Errorf("immutable release workflow omits %q", required)
		}
	}
	native := strings.Index(release, "  native:\n")
	attest := strings.Index(release, "  attest:\n")
	publish := strings.Index(release, "  publish:\n")
	if native < 0 || attest < native || publish < attest ||
		!strings.Contains(release[attest:publish], "- native") ||
		!strings.Contains(release[publish:], "- native") ||
		!strings.Contains(release[publish:], "- attest") {
		t.Fatal("attestation and publication do not depend on the native Apple Silicon gate")
	}
}

func TestPromotedArtifactAcceptanceCoversSandboxShell(t *testing.T) {
	acceptance := readRepositoryFile(t, "..", filepath.Join("acceptance", "promoted_artifact_native_test.go"))
	for _, required := range []string{
		"assertPromotedArtifactSandboxShell",
		`"sandbox", "--profile", "reviews", "--dry-run"`,
		`"sandbox", "--profile", "reviews"`,
		"test ! -e \\\"$HOME/.local/share/devin/credentials.toml\\\"",
		"sandbox-descendant.pid",
		"assertNoSessions(t, home)",
	} {
		if !strings.Contains(acceptance, required) {
			t.Errorf("installed-artifact acceptance omits %q", required)
		}
	}
}

func TestGenericRunDocumentationAndCandidateGateStayBoundToLiteralContainment(t *testing.T) {
	document := readRepositoryFile(t, "..", filepath.Join("docs", "guides", "generic-run.md"))
	for _, required := range []string{
		"acs run --profile backend-review -- /usr/bin/git status",
		"/usr/local/bin:/usr/bin:/bin",
		"workspace-relative executable must",
		"does not infer a filesystem or network grant catalog",
		"not a claim that path-based execution provides an atomic kernel",
	} {
		if !strings.Contains(document, required) {
			t.Errorf("generic run documentation omits %q", required)
		}
	}
	acceptance := readRepositoryFile(t, "..", filepath.Join("acceptance", "promoted_artifact_native_test.go"))
	for _, required := range []string{
		"assertPromotedArtifactGenericRun",
		"--acs-generic-command-helper",
		"private-argument-must-not-appear",
		"generic-descendant.pid",
		"generic-pty-size:97:31",
	} {
		if !strings.Contains(acceptance, required) {
			t.Errorf("generic candidate acceptance omits %q", required)
		}
	}
	workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	sharedGates := readRepositoryFile(t, "..", filepath.Join("scripts", "run-native-candidate-gates.sh"))
	if !strings.Contains(workflow, "scripts/run-native-candidate-gates.sh") ||
		!strings.Contains(sharedGates, "run_acceptance_test ./acceptance -count=1") {
		t.Fatal("promoted candidate gate omits the unfiltered installed-candidate acceptance")
	}
}

func TestPromotedArtifactGateUsesLockedNativeAuthenticationTargets(t *testing.T) {
	workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	sharedGates := readRepositoryFile(t, "..", filepath.Join("scripts", "run-native-candidate-gates.sh"))
	for _, required := range []string{
		"scripts/fetch-codex-test-targets.sh scripts/codex-test-targets.lock dist/codex-test-targets",
		"codex-test-targets-${{ github.sha }}",
		"scripts/install-codex-test-target.sh",
		"scripts/run-native-candidate-gates.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("promoted-artifact workflow omits native authentication guard %q", required)
		}
	}
	for _, required := range []string{
		"ACS_RUN_NATIVE_AUTH_GATE=1",
		"ACS_TEST_CODEX_BINARY",
		"run_auth_test ./internal/codexauthresource -run '^TestNativeKeychainCredentialFreeContract$'",
		"run_auth_test ./internal/codexauthresource -run '^TestNativeRealStoreInstalledTargetComposition$'",
		"run_auth_test ./internal/executor -run '^TestNativeInstalledTargetContainedStatusWithoutCredentials$'",
		"ACS_NATIVE_AUTH_RECOVERY_ROOT",
		"ACS_RUN_NATIVE_AUTH_RECOVERY=1",
		"TestNativeKeychainRecoveryEntrypoint",
	} {
		if !strings.Contains(sharedGates, required) {
			t.Errorf("shared native gate omits authentication guard %q", required)
		}
	}
	if strings.Count(workflow, "scripts/fetch-codex-test-targets.sh") != 1 {
		t.Fatal("official authentication targets must be fetched exactly once in the build-once candidate job")
	}
	for _, forbidden := range []string{"secrets.", "actions/upload-artifact" + "@" + "master"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("promoted-artifact workflow contains unsafe authentication gate content %q", forbidden)
		}
	}
}

func TestReleaseAndPromotedWorkflowsExecuteOneSharedNativeGate(t *testing.T) {
	for _, workflowName := range []string{"promoted-artifacts.yml", "release.yml"} {
		workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", workflowName))
		for _, required := range []string{
			"scripts/fetch-codex-test-targets.sh scripts/codex-test-targets.lock dist/codex-test-targets",
			"scripts/install-codex-test-target.sh",
			"scripts/run-native-candidate-gates.sh",
			"official checksum-locked Codex CLI",
			"synthetic authentication and a local simulated API",
			"real daily-use observation remains pending",
		} {
			if !strings.Contains(workflow, required) {
				t.Errorf("%s omits shared native release behavior %q", workflowName, required)
			}
		}
		if strings.Count(workflow, "scripts/fetch-codex-test-targets.sh") != 1 {
			t.Errorf("%s must fetch the locked target exactly once", workflowName)
		}
		if strings.Count(workflow, "scripts/run-native-candidate-gates.sh") != 1 {
			t.Errorf("%s must execute the shared native gate exactly once", workflowName)
		}
	}
}

func TestNamedAuthenticationDocumentationSeparatesAutomatedAndAuthenticatedEvidence(t *testing.T) {
	for _, document := range []string{
		"docs/development/testing.md",
	} {
		contents := readRepositoryFile(t, "..", document)
		normalized := strings.Join(strings.Fields(contents), " ")
		for _, required := range []string{
			"credential-free",
			"reviewed",
			"prohibit authentication UI",
			"supplemental",
		} {
			if !strings.Contains(normalized, required) {
				t.Errorf("%s omits evidence boundary %q", document, required)
			}
		}
		lower := strings.ToLower(normalized)
		if !strings.Contains(lower, "locked or unavailable") && !strings.Contains(lower, "locked/unavailable") {
			t.Errorf("%s omits the locked/unavailable Keychain boundary", document)
		}
	}
	workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	if !strings.Contains(workflow, "live locked-Keychain and ACL probes remain supplemental") {
		t.Fatal("native workflow summary omits the locked-Keychain evidence boundary")
	}
	smoke := strings.Join(strings.Fields(readRepositoryFile(t, "..", "docs/development/testing.md")), " ")
	if strings.Contains(smoke, "credential-free namespace, size, collision, locked-Keychain") {
		t.Fatal("authenticated smoke claims live locked-Keychain coverage is automated")
	}
	for _, required := range []string{"must not run in CI", "target-origin token refresh", "must not be recorded"} {
		if !strings.Contains(smoke, required) {
			t.Errorf("authenticated named-auth smoke omits safety boundary %q", required)
		}
	}
}

func TestSharedTargetConformanceDocumentationAndNativeGateStayExplicit(t *testing.T) {
	guide := readRepositoryFile(t, "..", "docs/reference/shared-target-conformance.md")
	normalizedGuide := strings.Join(strings.Fields(guide), " ")
	for _, required := range []string{
		"source` plus `relativePath",
		"read-only or explicit read-write",
		".acs/common/v1/skills",
		".codex/skills/<source>/<relativePath>",
		"no fallback to global Codex authentication",
		"before discovery, target execution, or Session creation",
		"../internal/adapter/conformance_test.go",
		"../scripts/run-native-candidate-gates.sh",
		"supplied ACS candidate without rebuilding it",
		"Portable fixtures do not establish real target discovery or native containment",
	} {
		if !strings.Contains(normalizedGuide, required) {
			t.Errorf("shared target guide omits %q", required)
		}
	}
	for _, document := range []string{"docs/reference/common-profile-format.md", "docs/guides/codex.md"} {
		if !strings.Contains(readRepositoryFile(t, "..", document), "shared-target-conformance.md") {
			t.Errorf("%s does not link the shared target guide", document)
		}
	}
	workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	sharedGates := readRepositoryFile(t, "..", filepath.Join("scripts", "run-native-candidate-gates.sh"))
	for _, required := range []string{
		"scripts/run-native-candidate-gates.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("promoted artifact workflow omits shared target gate %q", required)
		}
	}
	for _, required := range []string{"run_acceptance_test ./acceptance -count=1", "ACS_PROMOTED_BINARY"} {
		if !strings.Contains(sharedGates, required) {
			t.Errorf("shared native gate omits shared target coverage %q", required)
		}
	}
}

func TestContributorReleaseProcedurePreservesSafetyBoundaries(t *testing.T) {
	contributing := strings.Join(strings.Fields(
		readRepositoryFile(t, "..", "docs/development/releasing.md")+
			readRepositoryFile(t, "..", "docs/development/testing.md")), " ")
	for _, required := range []string{
		"docs/releases/vMAJOR.MINOR.PATCH.md",
		"explicit authorization for the tag push",
		"no later approval pause",
		"Never move or delete a release tag",
		"not an attestation subject",
		"Never strip quarantine",
		"archive-member digest is only an expected value",
		"An expired artifact must be replaced by a newly identified build",
		"never infer it from automated or publication success",
	} {
		if !strings.Contains(contributing, required) {
			t.Errorf("contributor procedure omits safety boundary %q", required)
		}
	}
}

func readRepositoryFile(t *testing.T, repository, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repository, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

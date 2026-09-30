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
		"docs/architecture.md",
		"docs/manual-upgrade-recovery.md",
	} {
		contents := readRepositoryFile(t, repository, document)
		if len(strings.TrimSpace(contents)) == 0 {
			t.Errorf("current document %s is empty", document)
		}
	}

	readme := readRepositoryFile(t, repository, "README.md")
	for _, required := range []string{
		"acs sandbox --profile",
		"/bin/zsh -f",
		"macOS 26",
		"darwin/arm64",
		"Apple Silicon",
		"There is no unsandboxed fallback",
		"ACS is not an egress firewall",
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README.md omits current contract %q", required)
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

func TestReleaseArtifactContractIsExactlyOneAppleSiliconTarget(t *testing.T) {
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
		if strings.Count(text, "sandbox_backend: available") != 1 {
			t.Errorf("%s does not declare exactly one native target", workflow)
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
	if strings.Contains(goreleaser, "      - linux") || strings.Count(goreleaser, "      - darwin") != 1 {
		t.Fatal("GoReleaser target matrix is not macOS-only")
	}
	candidate := readRepositoryFile(t, repository, filepath.Join("scripts", "release-candidate.sh"))
	for _, archive := range []string{"darwin_arm64.tar.gz"} {
		if !strings.Contains(candidate, archive) {
			t.Errorf("release candidate script omits %s", archive)
		}
	}
	if strings.Contains(candidate, "darwin_amd64.tar.gz") {
		t.Fatal("release candidate script still stages an Intel archive")
	}
	if strings.Contains(candidate, "linux_") {
		t.Fatal("release candidate script still publishes a Linux archive")
	}
	installer := readRepositoryFile(t, repository, filepath.Join("scripts", "install.sh.tmpl"))
	if strings.Contains(installer, "Linux) target_os") || !strings.Contains(installer, "ACS release installers support macOS only") {
		t.Fatal("installer does not reject unsupported Linux hosts clearly")
	}
}

func TestDevelopmentCandidateVersionHasReleaseNotes(t *testing.T) {
	repository := ".."
	promoted := readRepositoryFile(t, repository, filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	macos := readRepositoryFile(t, repository, filepath.Join(".github", "workflows", "macos.yml"))
	if !strings.Contains(promoted, "ACS_CANDIDATE_VERSION: v0.5.0") {
		t.Fatal("promoted workflow does not use the v0.5.0 development identity")
	}
	if !strings.Contains(macos, "scripts/release-candidate.sh v0.5.0") {
		t.Fatal("macOS workflow does not verify the v0.5.0 candidate")
	}
	for _, stale := range []string{
		"ACS_CANDIDATE_VERSION: v0.4.0",
		"scripts/release-candidate.sh v0.4.0",
	} {
		if strings.Contains(promoted, stale) || strings.Contains(macos, stale) {
			t.Fatalf("development workflow retains stale candidate identity %q", stale)
		}
	}

	notes := readRepositoryFile(t, repository, filepath.Join("docs", "releases", "v0.5.0.md"))
	if strings.TrimSpace(notes) == "" {
		t.Fatal("current candidate release notes are empty")
	}
	for _, script := range []string{"prepare-release-tag.sh", "release-tag-identity.sh"} {
		contents := readRepositoryFile(t, repository, filepath.Join("scripts", script))
		if !strings.Contains(contents, `release_notes="docs/releases/$release_tag.md"`) {
			t.Errorf("%s no longer validates version-controlled release notes", script)
		}
	}
}

func TestPortableSourceCompilationDoesNotExecuteUnsupportedRuntime(t *testing.T) {
	ci := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "ci.yml"))
	for _, required := range []string{
		"Compile portable source (non-blocking)",
		"continue-on-error: true",
		"CGO_ENABLED=0 go test -c",
		"CGO_ENABLED=0 go build",
	} {
		if !strings.Contains(ci, required) {
			t.Errorf("Portable compilation omits %q", required)
		}
	}
	for _, forbidden := range []string{"go test ./...", "go test -race ./...", "go test -run", "Bubblewrap", "release-candidate.sh"} {
		if strings.Contains(ci, forbidden) {
			t.Errorf("Portable compilation is still a support gate through %q", forbidden)
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
	document := readRepositoryFile(t, "..", filepath.Join("docs", "generic-run.md"))
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
		"CONTRIBUTING.md",
		"docs/codex.md",
	} {
		contents := readRepositoryFile(t, "..", document)
		normalized := strings.Join(strings.Fields(contents), " ")
		for _, required := range []string{
			"credential-free",
			"0.149.1",
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
	smoke := strings.Join(strings.Fields(readRepositoryFile(t, "..", "CONTRIBUTING.md")), " ")
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
	guide := readRepositoryFile(t, "..", "docs/shared-target-conformance.md")
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
	for _, document := range []string{"README.md", "docs/common-profile-format.md", "docs/codex.md"} {
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
	contributing := strings.Join(strings.Fields(readRepositoryFile(t, "..", "CONTRIBUTING.md")), " ")
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

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentDocumentationDefinesTheV040MacOSSandboxShellContract(t *testing.T) {
	repository := ".."
	for _, document := range []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/authenticated-release-smoke.md",
		"docs/releases/v0.4.0.md",
		"docs/releases/v0.4.0-checklist.md",
	} {
		contents := readRepositoryFile(t, repository, document)
		if len(strings.TrimSpace(contents)) == 0 {
			t.Errorf("current document %s is empty", document)
		}
	}

	readme := readRepositoryFile(t, repository, "README.md")
	for _, required := range []string{
		"v0.4.0",
		"acs sandbox --profile",
		"/bin/zsh -f",
		"macOS 26",
		"darwin/arm64",
		"Apple Silicon",
		"v0.3.3 is the final release with Linux support",
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
			"go test -count=1 -v -timeout=7m -race ./...",
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
	if strings.Contains(installer, "Linux) target_os") || !strings.Contains(installer, "ACS v0.4 supports macOS only") {
		t.Fatal("installer does not reject unsupported Linux hosts clearly")
	}
}

func TestLinuxIsOnlyANonBlockingCompileObservation(t *testing.T) {
	ci := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "ci.yml"))
	for _, required := range []string{
		"Observe Linux portability (non-blocking)",
		"continue-on-error: true",
		"go test -run '^$' ./...",
		"CGO_ENABLED=0 go build",
	} {
		if !strings.Contains(ci, required) {
			t.Errorf("Linux observation omits %q", required)
		}
	}
	for _, forbidden := range []string{"go test ./...", "go test -race ./...", "Bubblewrap", "release-candidate.sh"} {
		if strings.Contains(ci, forbidden) {
			t.Errorf("Linux observation is still a support gate through %q", forbidden)
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
		"multi-project real-use",
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
		"docs/codex-auth.md",
		"docs/authenticated-codex-auth-smoke.md",
	} {
		contents := readRepositoryFile(t, "..", document)
		normalized := strings.Join(strings.Fields(contents), " ")
		for _, required := range []string{
			"credential-free",
			"0.149.1",
			"prohibit authentication UI",
			"locked or unavailable",
			"supplemental",
		} {
			if !strings.Contains(normalized, required) {
				t.Errorf("%s omits evidence boundary %q", document, required)
			}
		}
	}
	workflow := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", "promoted-artifacts.yml"))
	if !strings.Contains(workflow, "live locked-Keychain and ACL probes remain supplemental") {
		t.Fatal("native workflow summary omits the locked-Keychain evidence boundary")
	}
	smoke := readRepositoryFile(t, "..", "docs/authenticated-codex-auth-smoke.md")
	if strings.Contains(smoke, "credential-free namespace, size, collision, locked-Keychain") {
		t.Fatal("authenticated smoke claims live locked-Keychain coverage is automated")
	}
	for _, required := range []string{"must not run in CI", "target-origin token refresh", "must not be recorded"} {
		if !strings.Contains(smoke, required) {
			t.Errorf("authenticated named-auth smoke omits safety boundary %q", required)
		}
	}
	authDocumentation := strings.Join(strings.Fields(readRepositoryFile(t, "..", "docs/codex-auth.md")), " ")
	for _, required := range []string{
		"deterministic private recovery root",
		"explicit empty list",
		"fresh process",
		"strictly validated relative state-directory component",
		"locator is removed last",
		"stable recovery categories",
	} {
		if !strings.Contains(authDocumentation, required) {
			t.Errorf("named-auth documentation omits isolated Keychain recovery guidance %q", required)
		}
	}
	if strings.Contains(authDocumentation, "reports the deterministic locator path") {
		t.Fatal("named-auth documentation instructs the recovery entrypoint to expose a private locator path")
	}
}

func TestSharedTargetConformanceDocumentationAndNativeGateStayExplicit(t *testing.T) {
	guide := readRepositoryFile(t, "..", "docs/shared-target-conformance.md")
	normalizedGuide := strings.Join(strings.Fields(guide), " ")
	for _, required := range []string{
		"source` plus `relativePath",
		"read-only or explicit read-write",
		"TestMaintainedTargetsShareCommonSkillsAndWorkspaceContract",
		"TestPromotedArtifactSharedTargetConformance",
		"supplied ACS candidate without rebuilding it",
		"ten minutes",
		"two real projects",
		"one week",
		"unperformed/pending",
		"Development source revision (commit SHA):",
		"ACS artifact version and SHA-256",
		"Target version:",
		"historical published v0.4.0 binary that predates them",
		"TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity",
		"no credentials, account data, target output, paths or Session contents",
	} {
		if !strings.Contains(normalizedGuide, required) {
			t.Errorf("shared target guide omits %q", required)
		}
	}
	for _, document := range []string{"README.md", "docs/common-profile-format.md", "docs/interactive-codex.md"} {
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

func TestHistoricalReleaseRecordsRemainAvailable(t *testing.T) {
	for _, version := range []string{"v0.2.0", "v0.3.0", "v0.3.1", "v0.3.2", "v0.3.3"} {
		for _, suffix := range []string{".md", "-checklist.md"} {
			document := filepath.Join("docs", "releases", version+suffix)
			if strings.TrimSpace(readRepositoryFile(t, "..", document)) == "" {
				t.Errorf("historical release record %s is empty", document)
			}
		}
	}
}

func TestDevelopmentWorkflowsBuildTheV040Candidate(t *testing.T) {
	for _, workflow := range []string{"macos.yml", "promoted-artifacts.yml"} {
		text := readRepositoryFile(t, "..", filepath.Join(".github", "workflows", workflow))
		if !strings.Contains(text, "v0.4.0") {
			t.Errorf("%s does not build the v0.4.0 candidate", workflow)
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

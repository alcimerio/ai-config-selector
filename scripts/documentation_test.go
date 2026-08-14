package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV020DocumentationUsesOneSupportAndInstallationContract(t *testing.T) {
	repository := filepath.Clean("..")
	documents := []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/releases/v0.2.0.md",
		"docs/releases/v0.2.0-checklist.md",
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

func TestV020ReleaseNotesMatchTagWorkflowPath(t *testing.T) {
	notes := filepath.Join("..", "docs", "releases", "v0.2.0.md")
	info, err := os.Stat(notes)
	if err != nil {
		t.Fatalf("stat release notes: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("v0.2.0 release notes are empty")
	}

	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	if !strings.Contains(string(workflow), `"docs/releases/$GITHUB_REF_NAME.md"`) {
		t.Fatal("release workflow no longer consumes version-controlled tag notes")
	}
}

func TestV020ReleaseUsesSoloMaintainerAuthorizationBoundary(t *testing.T) {
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
		"scripts/prepare-release-tag.sh v0.2.0",
		"git push origin refs/tags/v0.2.0",
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
		"docs/releases/v0.2.0-checklist.md",
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

func TestV020DefaultInstallVerificationDoesNotAssumePATH(t *testing.T) {
	for _, document := range []string{"README.md", "docs/releases/v0.2.0.md"} {
		contents, err := os.ReadFile(filepath.Join("..", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		if !strings.Contains(string(contents), `"$HOME/.local/bin/acs" version`) {
			t.Errorf("%s does not verify the default installed binary by exact path", document)
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

func TestPromotedArtifactGateDeclaresExpectedSandboxCapability(t *testing.T) {
	for _, workflow := range []string{"promoted-artifacts.yml", "release.yml"} {
		contents, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflow))
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		text := string(contents)
		if got := strings.Count(text, "sandbox_backend: unavailable"); got != 2 {
			t.Errorf("%s declares unavailable sandbox capability %d times, want 2", workflow, got)
		}
		if got := strings.Count(text, "sandbox_backend: available"); got != 2 {
			t.Errorf("%s declares available sandbox capability %d times, want 2", workflow, got)
		}
		if !strings.Contains(text, "ACS_PROMOTED_SANDBOX_BACKEND: ${{ matrix.sandbox_backend }}") {
			t.Errorf("%s does not pass the target sandbox capability to installed-artifact acceptance", workflow)
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
			"sudo apt-get update",
			"sudo apt-get install --yes --no-install-recommends bubblewrap",
			`[[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap && -x /usr/bin/bwrap ]]`,
			`stat --format='%u:%a' /usr/bin/bwrap`,
			`/usr/bin/dpkg-query --search /usr/bin/bwrap`,
			`/usr/bin/dpkg --verify --verify-format=rpm bubblewrap`,
			workflow.architectureCheck,
		} {
			if got := strings.Count(text, setup); got != 1 {
				t.Errorf("%s contains Ubuntu Bubblewrap setup %q %d times, want 1", workflow.name, setup, got)
			}
		}
		if workflow.platformGuard != "" && strings.Count(text, workflow.platformGuard) != 1 {
			t.Errorf("%s does not restrict Ubuntu Bubblewrap setup to its Linux matrix entries", workflow.name)
		}
		if strings.Index(text, "sudo apt-get install --yes --no-install-recommends bubblewrap") > strings.Index(text, "go test ./...") {
			t.Errorf("%s installs Bubblewrap after native tests", workflow.name)
		}
	}
}

func TestReadmeDescribesCurrentPlatformSandboxCapabilities(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := strings.Join(strings.Fields(string(contents)), " ")
	for _, required := range []string{
		"Ubuntu 24.04",
		"`/usr/bin/bwrap`",
		"signed Ubuntu `bubblewrap` package",
		"package database and packaged checksums are controlled by root",
		"outbound IP networking",
		"host Unix sockets",
		"Seatbelt backend in #57",
		"`backend_unavailable`",
		"before it leases a Session or starts Devin",
		"removes the Session after Devin exits or launch fails",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("README.md does not explain the sandbox launch state with %q", required)
		}
	}

}

func TestContributorRaceGateKeepsTheExceptionLinuxOnly(t *testing.T) {
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
}

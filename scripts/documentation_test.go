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
			"sudo apt-get update",
			"sudo apt-get install --yes --no-install-recommends apparmor apparmor-utils bubblewrap",
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
		if strings.Index(text, "sudo apt-get install --yes --no-install-recommends apparmor apparmor-utils bubblewrap") > strings.Index(text, "go test ./...") {
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
		"only the three Darwin tests that execute the race-instrumented test binary",
		"preceding non-race native suite and the installed promoted-artifact acceptance",
	} {
		if !strings.Contains(normalized, want) {
			t.Errorf("CONTRIBUTING.md is missing the macOS race rationale %q", want)
		}
	}
}

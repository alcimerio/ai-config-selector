package devin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestDiscoverGlobalSkillCatalogKeepsSourceIdentityForDuplicateNames(t *testing.T) {
	existingHome := t.TempDir()
	devinBundle := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	agentsBundle := filepath.Join(existingHome, ".agents", "skills", "review")
	invalidBundle := filepath.Join(existingHome, ".config", "devin", "skills", "not-a-skill")
	for _, bundlePath := range []string{devinBundle, agentsBundle, invalidBundle} {
		if err := os.MkdirAll(bundlePath, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, bundlePath := range []string{devinBundle, agentsBundle} {
		if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.DiscoverGlobalSkillCatalog(context.Background())
	if err != nil {
		t.Fatalf("discover global Skill Catalog: %v", err)
	}
	want := []skills.SkillBundle{
		{
			Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
			DisplayName: "review",
			BundlePath:  devinBundle,
		},
		{
			Reference:   skills.SkillReference{Source: "shared-agents", RelativePath: "review"},
			DisplayName: "review",
			BundlePath:  agentsBundle,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("global Skill Catalog = %#v, want %#v", got, want)
	}
}

func TestConfigDoesNotExposeProcessSandboxOverride(t *testing.T) {
	sandboxType := reflect.TypeOf((*launch.ProcessSandbox)(nil)).Elem()
	configType := reflect.TypeOf(Config{})
	for index := 0; index < configType.NumField(); index++ {
		field := configType.Field(index)
		if field.IsExported() && field.Type.Implements(sandboxType) {
			t.Fatalf("Config exposes ProcessSandbox override %q", field.Name)
		}
	}
}

func TestPreflightReportsSanitizedCatalogMismatch(t *testing.T) {
	fixture := newFakeDevinFixture(t, []fakeObservedSkill{{
		Name:     "token=SUPER_SECRET_STDOUT",
		Provider: "Devin",
		BaseDir:  filepath.Join(plannedSessionHome(t), ".config", "devin", "skills", "SUPER_SECRET_PATH"),
	}}, "Logged in (via Devin).", 0)
	fixture.skillsStderr = "credential=SUPER_SECRET_CATALOG_OUTPUT"

	adapter, session := fixture.prepare(t)
	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded with the wrong global Skill Catalog")
	}

	var preflightError *PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *PreflightError", err)
	}
	if preflightError.Capability != CapabilitySkillIsolation {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, CapabilitySkillIsolation)
	}
	diagnostic := err.Error()
	for _, required := range []string{"skill isolation", "incompatible"} {
		if !strings.Contains(diagnostic, required) {
			t.Errorf("diagnostic %q does not contain actionable detail %q", diagnostic, required)
		}
	}
	for _, sensitive := range []string{"SUPER_SECRET_CATALOG_OUTPUT", "SUPER_SECRET_STDOUT", "SUPER_SECRET_PATH", "acs-selected-fixture"} {
		if strings.Contains(diagnostic, sensitive) {
			t.Errorf("diagnostic leaked catalog data: %q", diagnostic)
		}
	}
}

func TestPreflightPreservesStableSandboxFailureCategory(t *testing.T) {
	adapter, err := newAdapter(Config{
		BinaryPath: "devin", ExistingHomeDir: t.TempDir(),
	}, setupFailureSandbox{})
	if err != nil {
		t.Fatal(err)
	}
	workingDirectory := t.TempDir()
	session, err := adapter.PrepareSession(filepath.Join(t.TempDir(), "session"), workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.Preflight(context.Background(), session)
	var sandboxFailure *launch.SandboxError
	if !errors.As(err, &sandboxFailure) {
		t.Fatalf("Preflight error type = %T, want *launch.SandboxError: %v", err, err)
	}
	if sandboxFailure.Category != launch.SandboxSetupFailed {
		t.Fatalf("sandbox category = %q, want %q", sandboxFailure.Category, launch.SandboxSetupFailed)
	}
}

func TestPreflightSanitizesManagedSkillIdentities(t *testing.T) {
	fixture := newFakeDevinFixture(t, nil, "Logged in (via Devin).", 0)
	fixture.selectedRelativePath = "acs-selected\n\x1b[31mforged"

	adapter, session := fixture.prepare(t)
	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded with a missing selected Skill Bundle")
	}
	if strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("diagnostic contains terminal control characters: %q", err.Error())
	}
}

func TestPreflightDoesNotExposeManagedCatalogIdentities(t *testing.T) {
	fixture := newFakeDevinFixture(t, []fakeObservedSkill{{
		Name:     "café",
		Provider: "Devin",
		BaseDir:  filepath.Join(plannedSessionHome(t), ".config", "devin", "skills", "café"),
	}}, "Logged in (via Devin).", 0)
	fixture.selectedRelativePath = "caf"

	adapter, session := fixture.prepare(t)
	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded with different managed Skill References")
	}
	diagnostic := err.Error()
	for _, identity := range []string{"caf", "café", `caf\u00e9`} {
		if strings.Contains(diagnostic, identity) {
			t.Fatalf("diagnostic exposed a managed catalog identity: %q", diagnostic)
		}
	}
}

func TestPreflightReportsMissingExecutableInsteadOfSuggestingLoginOrCommandSupport(t *testing.T) {
	fixture := newFakeDevinFixture(t, nil, "", 0)
	adapter, session := fixture.prepare(t)
	if err := os.Remove(filepath.Join(fixture.testRoot, "fake-devin")); err != nil {
		t.Fatal(err)
	}

	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded without a Devin executable")
	}
	diagnostic := err.Error()
	if !strings.Contains(diagnostic, "executable") || !strings.Contains(diagnostic, "installed") {
		t.Fatalf("missing-executable diagnostic is not actionable: %q", diagnostic)
	}
	if strings.Contains(diagnostic, "auth login") || strings.Contains(diagnostic, "supports `devin skills") {
		t.Fatalf("missing-executable diagnostic suggests the wrong remedy: %q", diagnostic)
	}
}

func TestPreflightReportsSanitizedUnavailableAuthentication(t *testing.T) {
	fixture := newFakeDevinFixture(t, []fakeObservedSkill{{
		Name:     "acs-selected-fixture",
		Provider: "Devin",
		BaseDir:  filepath.Join(plannedSessionHome(t), ".config", "devin", "skills", "acs-selected-fixture"),
	}}, "Not logged in. account=PRIVATE_ACCOUNT token=SUPER_SECRET", 0)

	adapter, session := fixture.prepare(t)
	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded without usable authentication")
	}

	var preflightError *PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *PreflightError", err)
	}
	if preflightError.Capability != CapabilityAuthentication {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, CapabilityAuthentication)
	}
	diagnostic := err.Error()
	if !strings.Contains(diagnostic, "devin auth login") {
		t.Errorf("diagnostic is not actionable: %q", diagnostic)
	}
	for _, privateValue := range []string{"PRIVATE_ACCOUNT", "SUPER_SECRET"} {
		if strings.Contains(diagnostic, privateValue) {
			t.Errorf("diagnostic leaked authentication output: %q", diagnostic)
		}
	}
}

func TestPreflightExcludesProjectLocalSkillsFromManagedGlobalCatalog(t *testing.T) {
	projectBundle := filepath.Join(plannedWorkingDirectory(t), ".agents", "skills", "project-local")
	if err := os.MkdirAll(projectBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectBundle, "SKILL.md"), []byte("# project local\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fixture := newFakeDevinFixture(t, []fakeObservedSkill{
		{
			Name:     "acs-selected-fixture",
			Provider: "Devin",
			BaseDir:  filepath.Join(plannedSessionHome(t), ".config", "devin", "skills", "acs-selected-fixture"),
		},
		{
			Name:     "project-local",
			Provider: "Devin",
			BaseDir:  projectBundle,
		},
	}, "Logged in (via Devin).", 0)

	adapter, session := fixture.prepare(t)
	if err := adapter.Preflight(context.Background(), session); err != nil {
		t.Fatalf("project-local skill changed the managed global catalog: %v", err)
	}
}

func TestPrepareSessionCopiesOnlySelectedBundlesAndCredentialAllowlist(t *testing.T) {
	fixture := newFakeDevinFixture(t, nil, "", 0)
	if err := os.MkdirAll(filepath.Join(fixture.existingHome, ".config", "devin", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	privateConfig := filepath.Join(fixture.existingHome, ".config", "devin", "config.json")
	if err := os.WriteFile(privateConfig, []byte(`{"unrestricted":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, session := fixture.prepare(t)
	credentialPath := filepath.Join(session.HomeDir, ".local", "share", "devin", "credentials.toml")
	credential, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatalf("read allowlisted credential: %v", err)
	}
	if string(credential) != "fixture-credential" {
		t.Fatal("prepared credential differs from the explicitly allowlisted source")
	}
	credentialInfo, err := os.Stat(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if credentialInfo.Mode().Perm() != 0o600 {
		t.Errorf("credential permissions = %o, want 600", credentialInfo.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(session.HomeDir, ".config", "devin", "config.json")); !os.IsNotExist(err) {
		t.Fatal("PrepareSession copied the unrestricted Devin configuration")
	}
	if _, err := os.Stat(filepath.Join(session.HomeDir, ".config", "devin", "hooks")); !os.IsNotExist(err) {
		t.Fatal("PrepareSession copied unrestricted Devin hooks")
	}
	for _, relativePath := range []string{
		filepath.Join("SKILL.md"),
		filepath.Join("references", "proof.txt"),
		filepath.Join("scripts", "prove.sh"),
	} {
		if _, err := os.Stat(filepath.Join(session.HomeDir, ".config", "devin", "skills", "acs-selected-fixture", relativePath)); err != nil {
			t.Errorf("selected Skill Bundle file %q was not copied: %v", relativePath, err)
		}
	}
	executable, err := os.Stat(filepath.Join(session.HomeDir, ".config", "devin", "skills", "acs-selected-fixture", "scripts", "prove.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if executable.Mode().Perm() != 0o755 {
		t.Errorf("selected Skill Bundle executable permissions = %o, want 755", executable.Mode().Perm())
	}
}

func TestPrepareSessionSanitizesCredentialPathFailures(t *testing.T) {
	sensitiveComponent := "PRIVATE_TOKEN_PATH" + strings.Repeat("x", 300)
	existingHome := filepath.Join(t.TempDir(), sensitiveComponent)
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.PrepareSession(t.TempDir(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("PrepareSession accepted an unreadable credential source")
	}
	for _, sensitive := range []string{"PRIVATE_TOKEN_PATH", sensitiveComponent, existingHome} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("credential failure exposed a sensitive path: %q", err)
		}
	}
}

func TestPrepareSessionPreservesRegularSymlinkBackedCredentials(t *testing.T) {
	root := t.TempDir()
	existingHome := filepath.Join(root, "existing-home")
	credentialPath := filepath.Join(existingHome, ".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(credentialPath), 0o700); err != nil {
		t.Fatal(err)
	}
	credentialTarget := filepath.Join(root, "credential-target")
	if err := os.WriteFile(credentialTarget, []byte("fixture-symlink-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(credentialTarget, credentialPath); err != nil {
		t.Fatal(err)
	}
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	session, err := adapter.PrepareSession(t.TempDir(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("PrepareSession rejected a regular symlink-backed credential: %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(session.HomeDir, ".local", "share", "devin", "credentials.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != "fixture-symlink-credential" {
		t.Fatal("PrepareSession copied unexpected credential bytes")
	}
}

func TestSourceRulesSeparateGlobalAndProjectLocalSkills(t *testing.T) {
	wantGlobal := []SourceRule{
		{Source: GlobalSourceDevinConfig, RelativeDirectory: filepath.Join(".config", "devin", "skills")},
		{Source: GlobalSourceSharedAgents, RelativeDirectory: filepath.Join(".agents", "skills")},
	}
	if got := GlobalSourceRules(); !reflect.DeepEqual(got, wantGlobal) {
		t.Fatalf("global source rules = %#v, want %#v", got, wantGlobal)
	}

	wantProject := []string{filepath.Join(".devin", "skills"), filepath.Join(".agents", "skills")}
	if got := ProjectSourceDirectories(); !reflect.DeepEqual(got, wantProject) {
		t.Fatalf("project source rules = %#v, want %#v", got, wantProject)
	}
}

type fakeObservedSkill struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseDir  string `json:"base_dir"`
}

type setupFailureSandbox struct{}

func (setupFailureSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (setupFailureSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	return nil, &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

type fakeDevinFixture struct {
	testRoot             string
	existingHome         string
	skills               []fakeObservedSkill
	skillsStderr         string
	authOutput           string
	authExitStatus       int
	selectedRelativePath string
}

func newFakeDevinFixture(t *testing.T, skills []fakeObservedSkill, authOutput string, authExitStatus int) *fakeDevinFixture {
	t.Helper()
	root := testRootPath(t)
	existingHome := filepath.Join(root, "existing-home")
	credentialPath := filepath.Join(existingHome, ".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(credentialPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, []byte("fixture-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeDevinFixture{
		testRoot:             root,
		existingHome:         existingHome,
		skills:               skills,
		authOutput:           authOutput,
		authExitStatus:       authExitStatus,
		selectedRelativePath: "acs-selected-fixture",
	}
}

func (fixture *fakeDevinFixture) prepare(t *testing.T) (*Adapter, *Session) {
	t.Helper()
	binaryPath := filepath.Join(fixture.testRoot, "fake-devin")
	skillsJSONPath := filepath.Join(fixture.testRoot, "skills.json")
	authOutputPath := filepath.Join(fixture.testRoot, "auth.txt")
	stderrPath := filepath.Join(fixture.testRoot, "skills-stderr.txt")

	skillsJSON, err := json.Marshal(fixture.skills)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		skillsJSONPath: skillsJSON,
		authOutputPath: []byte(fixture.authOutput),
		stderrPath:     []byte(fixture.skillsStderr),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  cat "$FAKE_DEVIN_SKILLS_JSON"
  cat "$FAKE_DEVIN_SKILLS_STDERR" >&2
  exit 0
fi
if [ "$1" = "auth" ]; then
  cat "$FAKE_DEVIN_AUTH_OUTPUT"
  exit "$FAKE_DEVIN_AUTH_EXIT"
fi
exit 64
`
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DEVIN_SKILLS_JSON", skillsJSONPath)
	t.Setenv("FAKE_DEVIN_SKILLS_STDERR", stderrPath)
	t.Setenv("FAKE_DEVIN_AUTH_OUTPUT", authOutputPath)
	t.Setenv("FAKE_DEVIN_AUTH_EXIT", strconv.Itoa(fixture.authExitStatus))

	adapter, err := newAdapter(Config{BinaryPath: binaryPath, ExistingHomeDir: fixture.existingHome}, directSandbox{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := adapter.PrepareSession(
		filepath.Join(fixture.testRoot, "session"),
		plannedWorkingDirectory(t),
		[]SkillBundle{{
			Reference: SkillReference{
				Source:       GlobalSourceDevinConfig,
				RelativePath: fixture.selectedRelativePath,
			},
			BundlePath: filepath.Join("testdata", "selected-skill"),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, session
}

func plannedSessionHome(t *testing.T) string {
	t.Helper()
	return filepath.Join(testRootPath(t), "session", "home")
}

func plannedWorkingDirectory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(testRootPath(t), "work")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRootPath(t *testing.T) string {
	t.Helper()
	if value := os.Getenv("ACS_TEST_ROOT_" + strings.ReplaceAll(t.Name(), "/", "_")); value != "" {
		return value
	}
	value := filepath.Join(t.TempDir(), "fixture")
	t.Setenv("ACS_TEST_ROOT_"+strings.ReplaceAll(t.Name(), "/", "_"), value)
	return value
}

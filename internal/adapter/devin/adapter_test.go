package devin_test

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

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
)

func TestPreflightReportsSanitizedCatalogMismatch(t *testing.T) {
	fixture := newFakeDevinFixture(t, []fakeObservedSkill{{
		Name:     "unselected",
		Provider: "Devin",
		BaseDir:  filepath.Join(plannedSessionHome(t), ".config", "devin", "skills", "unselected"),
	}}, "Logged in (via Devin).", 0)
	fixture.skillsStderr = "credential=SUPER_SECRET_CATALOG_OUTPUT"

	adapter, session := fixture.prepare(t)
	err := adapter.Preflight(context.Background(), session)
	if err == nil {
		t.Fatal("Preflight succeeded with the wrong global Skill Catalog")
	}

	var preflightError *devin.PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *devin.PreflightError", err)
	}
	if preflightError.Capability != devin.CapabilitySkillIsolation {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, devin.CapabilitySkillIsolation)
	}
	diagnostic := err.Error()
	for _, required := range []string{"devin-config:acs-selected-fixture", "devin-config:unselected", "incompatible"} {
		if !strings.Contains(diagnostic, required) {
			t.Errorf("diagnostic %q does not contain actionable detail %q", diagnostic, required)
		}
	}
	if strings.Contains(diagnostic, "SUPER_SECRET") {
		t.Errorf("diagnostic leaked subprocess output: %q", diagnostic)
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

	var preflightError *devin.PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *devin.PreflightError", err)
	}
	if preflightError.Capability != devin.CapabilityAuthentication {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, devin.CapabilityAuthentication)
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
}

func TestSourceRulesSeparateGlobalAndProjectLocalSkills(t *testing.T) {
	wantGlobal := []devin.SourceRule{
		{Source: devin.GlobalSourceDevinConfig, RelativeDirectory: filepath.Join(".config", "devin", "skills")},
		{Source: devin.GlobalSourceSharedAgents, RelativeDirectory: filepath.Join(".agents", "skills")},
	}
	if got := devin.GlobalSourceRules(); !reflect.DeepEqual(got, wantGlobal) {
		t.Fatalf("global source rules = %#v, want %#v", got, wantGlobal)
	}

	wantProject := []string{filepath.Join(".devin", "skills"), filepath.Join(".agents", "skills")}
	if got := devin.ProjectSourceDirectories(); !reflect.DeepEqual(got, wantProject) {
		t.Fatalf("project source rules = %#v, want %#v", got, wantProject)
	}
}

type fakeObservedSkill struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseDir  string `json:"base_dir"`
}

type fakeDevinFixture struct {
	testRoot       string
	existingHome   string
	skills         []fakeObservedSkill
	skillsStderr   string
	authOutput     string
	authExitStatus int
}

func newFakeDevinFixture(t *testing.T, skills []fakeObservedSkill, authOutput string, authExitStatus int) *fakeDevinFixture {
	t.Helper()
	root := testRoot(t)
	existingHome := filepath.Join(root, "existing-home")
	credentialPath := filepath.Join(existingHome, ".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(credentialPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, []byte("fixture-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeDevinFixture{
		testRoot:       root,
		existingHome:   existingHome,
		skills:         skills,
		authOutput:     authOutput,
		authExitStatus: authExitStatus,
	}
}

func (fixture *fakeDevinFixture) prepare(t *testing.T) (*devin.Adapter, *devin.Session) {
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

	adapter, err := devin.New(devin.Config{BinaryPath: binaryPath, ExistingHomeDir: fixture.existingHome})
	if err != nil {
		t.Fatal(err)
	}
	session, err := adapter.PrepareSession(
		filepath.Join(fixture.testRoot, "session"),
		plannedWorkingDirectory(t),
		[]devin.SkillBundle{{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "acs-selected-fixture",
			BundlePath:   filepath.Join("testdata", "selected-skill"),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, session
}

func testRoot(t *testing.T) string {
	t.Helper()
	return testRootPath(t)
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

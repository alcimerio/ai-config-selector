package devin

import (
	"context"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
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
		for _, forbidden := range []string{"sandbox", "backend", "unsandbox"} {
			if field.IsExported() && strings.Contains(strings.ToLower(field.Name), forbidden) {
				t.Fatalf("Config exposes a sandbox-selection or bypass field %q", field.Name)
			}
		}
	}
}

func TestSandboxAssemblyHasNoCrossPackageBypass(t *testing.T) {
	patterns := []string{
		filepath.Join("..", "devin", "*.go"),
		filepath.Join("..", "..", "cli", "*.go"),
	}
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, bypass := range []string{"go:" + "linkname", strconv.Quote("un" + "safe")} {
				if strings.Contains(string(source), bypass) {
					t.Fatalf("sandbox assembly bypass %q found in %s", bypass, path)
				}
			}
		}
	}
}

func TestPrepareSessionCopiesOnlySelectedBundlesAndCredentialAllowlist(t *testing.T) {
	fixture := newPreparationFixture(t)
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

type preparationFixture struct{ existingHome string }

func newPreparationFixture(t *testing.T) preparationFixture {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, ".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	return preparationFixture{existingHome: home}
}
func (fixture preparationFixture) prepare(t *testing.T) (*Adapter, *Session) {
	t.Helper()
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: fixture.existingHome})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := adapter.PrepareSession(t.TempDir(), t.TempDir(), []SkillBundle{{
		Reference:  SkillReference{Source: GlobalSourceDevinConfig, RelativePath: "acs-selected-fixture"},
		BundlePath: filepath.Join("testdata", "selected-skill"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, prepared
}

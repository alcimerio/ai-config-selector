package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestVerifyDevinAcceptsCanonicalManagedSkillPaths(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.catalog = func(request launch.ProcessRequest) []catalogObservedSkill {
		canonicalHome, err := filepath.EvalSymlinks(request.SessionHome)
		if err != nil {
			t.Fatal(err)
		}
		return []catalogObservedSkill{{Name: "acs-selected-fixture", Provider: "Devin", BaseDir: filepath.Join(canonicalHome, ".config", "devin", "skills", "acs-selected-fixture")}}
	}
	if err := fixture.verify(t); err != nil {
		t.Fatalf("VerifyDevin rejected canonical managed skill path from protected Session: %v", err)
	}
}

func TestPreflightRejectsManagedSourceRootSymlinkEscape(t *testing.T) {
	fixture := newCatalogFixture(t)
	externalRoot := filepath.Join(t.TempDir(), "external-skills")
	if err := os.MkdirAll(filepath.Join(externalRoot, "acs-selected-fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.beforeCatalog = func(request launch.ProcessRequest) {
		managedRoot := filepath.Join(request.SessionHome, ".config", "devin", "skills")
		if err := os.Rename(managedRoot, filepath.Join(t.TempDir(), "moved-managed-root")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(externalRoot, managedRoot); err != nil {
			t.Fatal(err)
		}
	}
	fixture.catalog = func(launch.ProcessRequest) []catalogObservedSkill {
		return []catalogObservedSkill{{Name: "acs-selected-fixture", Provider: "Devin", BaseDir: filepath.Join(externalRoot, "acs-selected-fixture")}}
	}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin accepted a managed source root symlink escape")
	}
	if strings.Contains(err.Error(), externalRoot) {
		t.Fatalf("VerifyDevin exposed the escaped source root: %q", err)
	}
}

func TestPreflightRejectsSelectedBundleSymlinkEscape(t *testing.T) {
	fixture := newCatalogFixture(t)
	externalBundle := filepath.Join(t.TempDir(), "external-selected-bundle")
	if err := os.MkdirAll(externalBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.beforeCatalog = func(request launch.ProcessRequest) {
		selected := filepath.Join(request.SessionHome, ".config", "devin", "skills", "acs-selected-fixture")
		if err := os.Rename(selected, filepath.Join(t.TempDir(), "moved-selected-bundle")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(externalBundle, selected); err != nil {
			t.Fatal(err)
		}
	}
	fixture.catalog = func(request launch.ProcessRequest) []catalogObservedSkill {
		return []catalogObservedSkill{{Name: "acs-selected-fixture", Provider: "Devin", BaseDir: filepath.Join(request.SessionHome, ".config", "devin", "skills", "acs-selected-fixture")}}
	}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin accepted a selected bundle symlink escape")
	}
	for _, sensitivePath := range []string{externalBundle} {
		if strings.Contains(err.Error(), sensitivePath) {
			t.Fatalf("VerifyDevin exposed a managed bundle path: %q", err)
		}
	}
}

func TestPreflightReportsSanitizedCatalogMismatch(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.catalog = func(request launch.ProcessRequest) []catalogObservedSkill {
		return []catalogObservedSkill{{Name: "token=SUPER_SECRET_STDOUT", Provider: "Devin", BaseDir: filepath.Join(request.SessionHome, ".config", "devin", "skills", "SUPER_SECRET_PATH")}}
	}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin succeeded with the wrong global Skill Catalog")
	}
	var preflightError *devinruntime.PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *devinruntime.PreflightError", err)
	}
	if preflightError.Capability != devinruntime.CapabilitySkillIsolation {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, devinruntime.CapabilitySkillIsolation)
	}
	diagnostic := err.Error()
	for _, required := range []string{"skill isolation", "incompatible"} {
		if !strings.Contains(diagnostic, required) {
			t.Errorf("diagnostic %q does not contain actionable detail %q", diagnostic, required)
		}
	}
	for _, sensitive := range []string{"SUPER_SECRET_STDOUT", "SUPER_SECRET_PATH", "acs-selected-fixture"} {
		if strings.Contains(diagnostic, sensitive) {
			t.Errorf("diagnostic leaked catalog data: %q", diagnostic)
		}
	}
}

func TestPreflightPreservesStableSandboxFailureCategory(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.sandbox.prepareErr = &launch.SandboxError{Category: launch.SandboxSetupFailed}
	err := fixture.verify(t)
	var sandboxFailure *launch.SandboxError
	if !errors.As(err, &sandboxFailure) {
		t.Fatalf("Preflight error type = %T, want *launch.SandboxError: %v", err, err)
	}
	if sandboxFailure.Category != launch.SandboxSetupFailed {
		t.Fatalf("sandbox category = %q, want %q", sandboxFailure.Category, launch.SandboxSetupFailed)
	}
}

func TestPreflightSanitizesManagedSkillIdentities(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.request.ExpectedCatalog = []skills.SkillReference{{Source: devinruntime.GlobalSourceDevinConfig, RelativePath: "acs-selected\n\x1b[31mforged"}}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin succeeded with a missing selected Skill Bundle")
	}
	if strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("diagnostic contains terminal control characters: %q", err.Error())
	}
}

func TestPreflightDoesNotExposeManagedCatalogIdentities(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.request.ExpectedCatalog = []skills.SkillReference{{Source: devinruntime.GlobalSourceDevinConfig, RelativePath: "caf"}}
	fixture.catalog = func(request launch.ProcessRequest) []catalogObservedSkill {
		return []catalogObservedSkill{{Name: "café", Provider: "Devin", BaseDir: filepath.Join(request.SessionHome, ".config", "devin", "skills", "café")}}
	}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin succeeded with different managed Skill References")
	}
	for _, identity := range []string{"caf", "café", `caf\u00e9`} {
		if strings.Contains(err.Error(), identity) {
			t.Fatalf("diagnostic exposed a managed catalog identity: %q", err)
		}
	}
}

func TestPreflightReportsMissingExecutableInsteadOfSuggestingLoginOrCommandSupport(t *testing.T) {
	fixture := newCatalogFixture(t)
	fixture.sandbox.prepareErr = &os.PathError{Op: "fork/exec", Path: "fake-devin", Err: os.ErrNotExist}
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin succeeded without a Devin executable")
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
	fixture := newCatalogFixture(t)
	fixture.auth = "Not logged in. account=PRIVATE_ACCOUNT token=SUPER_SECRET"
	err := fixture.verify(t)
	if err == nil {
		t.Fatal("VerifyDevin succeeded without usable authentication")
	}
	var preflightError *devinruntime.PreflightError
	if !errors.As(err, &preflightError) {
		t.Fatalf("Preflight error type = %T, want *devinruntime.PreflightError", err)
	}
	if preflightError.Capability != devinruntime.CapabilityAuthentication {
		t.Errorf("failed capability = %q, want %q", preflightError.Capability, devinruntime.CapabilityAuthentication)
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
	fixture := newCatalogFixture(t)
	projectBundle := filepath.Join(fixture.request.WorkingDirectory, ".agents", "skills", "project-local")
	if err := os.MkdirAll(projectBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectBundle, "SKILL.md"), []byte("# project local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.catalog = func(request launch.ProcessRequest) []catalogObservedSkill {
		return []catalogObservedSkill{{Name: "acs-selected-fixture", Provider: "Devin", BaseDir: filepath.Join(request.SessionHome, ".config", "devin", "skills", "acs-selected-fixture")}, {Name: "project-local", Provider: "Devin", BaseDir: projectBundle}}
	}
	if err := fixture.verify(t); err != nil {
		t.Fatalf("project-local skill changed the managed global catalog: %v", err)
	}
}

type catalogObservedSkill struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseDir  string `json:"base_dir"`
}

type catalogFixture struct {
	t             *testing.T
	request       DevinRequest
	sandbox       *catalogSandbox
	catalog       func(launch.ProcessRequest) []catalogObservedSkill
	auth          string
	beforeCatalog func(launch.ProcessRequest)
}

func newCatalogFixture(t *testing.T) *catalogFixture {
	t.Helper()
	working := t.TempDir()
	fixture := &catalogFixture{t: t, auth: "Logged in (via Devin)."}
	fixture.request = DevinRequest{SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: working, Executable: "fake-devin", ExpectedCatalog: []skills.SkillReference{{Source: devinruntime.GlobalSourceDevinConfig, RelativePath: "acs-selected-fixture"}}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
	fixture.request.Materializer = catalogMaterializer(func(home string) error {
		return os.MkdirAll(filepath.Join(home, ".config", "devin", "skills", "acs-selected-fixture"), 0o700)
	})
	fixture.sandbox = &catalogSandbox{fixture: fixture}
	return fixture
}

func (f *catalogFixture) verify(t *testing.T) error {
	t.Helper()
	err := newExecutor(f.sandbox).VerifyDevin(context.Background(), f.request)
	if f.sandbox.sessionHome == "" {
		t.Fatal("VerifyDevin did not create a protected Session")
	}
	if _, statErr := os.Stat(f.sandbox.sessionHome); !os.IsNotExist(statErr) {
		t.Fatalf("VerifyDevin did not clean up its Session home: %v", statErr)
	}
	return err
}

type catalogMaterializer func(string) error

func (f catalogMaterializer) Materialize(home string) error { return f(home) }

type catalogSandbox struct {
	fixture     *catalogFixture
	prepareErr  error
	sessionHome string
}

func (*catalogSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (*catalogSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (s *catalogSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	s.sessionHome = request.SessionHome
	if s.prepareErr != nil {
		return nil, s.prepareErr
	}
	if len(request.Arguments) > 0 && request.Arguments[0] == "skills" {
		if s.fixture.beforeCatalog != nil {
			s.fixture.beforeCatalog(request)
		}
		observed := s.fixture.catalog
		if observed == nil {
			observed = func(request launch.ProcessRequest) []catalogObservedSkill {
				return []catalogObservedSkill{{Name: "acs-selected-fixture", Provider: "Devin", BaseDir: filepath.Join(request.SessionHome, ".config", "devin", "skills", "acs-selected-fixture")}}
			}
		}
		output, err := json.Marshal(observed(request))
		if err != nil {
			return nil, err
		}
		return &catalogProcess{output: output, terminal: request.Terminal}, nil
	}
	if len(request.Arguments) > 0 && request.Arguments[0] == "auth" {
		return &catalogProcess{output: []byte(s.fixture.auth), terminal: request.Terminal}, nil
	}
	return nil, errors.New("unexpected Devin probe")
}

type catalogProcess struct {
	output   []byte
	terminal launch.Terminal
}

func (*catalogProcess) Start() error { return nil }
func (p *catalogProcess) Wait() error {
	if p.terminal.Output != nil {
		_, _ = p.terminal.Output.Write(p.output)
	}
	return nil
}
func (*catalogProcess) Signal(os.Signal) error { return nil }

func TestVerifyDevinRejectsAliasedSessionRootBeforePreparingProcess(t *testing.T) {
	fixture := newCatalogFixture(t)
	realRoot := t.TempDir()
	aliasRoot := filepath.Join(t.TempDir(), "sessions-alias")
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Fatal(err)
	}
	fixture.request.SessionsDirectory = aliasRoot
	err := newExecutor(fixture.sandbox).VerifyDevin(context.Background(), fixture.request)
	if err == nil || fixture.sandbox.sessionHome != "" {
		t.Fatalf("unsafe Session root = %v, prepared home = %q", err, fixture.sandbox.sessionHome)
	}
	if entries, err := os.ReadDir(realRoot); err != nil || len(entries) != 0 {
		t.Fatalf("aliased root was populated: %v %v", entries, err)
	}
}

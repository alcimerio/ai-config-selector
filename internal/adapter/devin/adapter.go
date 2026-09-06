// Package devin implements the Devin-specific boundary for ACS Sessions.
package devin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// GlobalSource identifies one explicit Devin user-global Skill Bundle source.
type GlobalSource = devinruntime.GlobalSource

const (
	GlobalSourceDevinConfig  = devinruntime.GlobalSourceDevinConfig
	GlobalSourceSharedAgents = devinruntime.GlobalSourceSharedAgents
)

// SourceRule records a Devin discovery rule relative to the Session home.
type SourceRule = devinruntime.SourceRule

const credentialsRelativePath = ".local/share/devin/credentials.toml"

// GlobalSourceRules returns the complete set of global Skill Catalog sources
// managed by the Devin Adapter. Project-local sources are deliberately absent.
func GlobalSourceRules() []SourceRule {
	return devinruntime.GlobalSourceRules()
}

// ProjectSourceDirectories returns Devin's known repository-local skill roots.
// ACS observes but does not materialize or filter these roots.
func ProjectSourceDirectories() []string {
	return devinruntime.ProjectSourceDirectories()
}

type Config struct {
	BinaryPath      string
	ExistingHomeDir string
	RuntimeInputs   []string
}

// devinExecutor is a private facade seam. Production always uses executor.New;
// callers cannot select a backend or supply process capabilities.
type devinExecutor interface {
	Readiness(context.Context) (launch.SandboxReadiness, error)
	RunDevin(context.Context, executor.DevinRequest) (int, error)
}

type Adapter struct {
	binaryPath        string
	existingHomeDir   string
	categories        *category.Registry
	editors           *builder.EditorRegistry
	skillsCategory    commonprofile.SkillsBinding
	workspaceCategory commonprofile.WorkspaceBinding
	executor          devinExecutor
	runtimeInputs     []string
}

type SkillBundle = skills.SkillBundle

// SkillReference is the stable source-plus-relative-path identity of one
// selected global Skill Bundle.
type SkillReference = skills.SkillReference

type Session struct {
	RootDir          string
	HomeDir          string
	TemporaryDir     string
	SessionsDir      string
	WorkingDirectory string

	expectedCatalog []SkillReference
}

func New(config Config) (*Adapter, error) {
	adapter, err := newAdapter(config)
	if err != nil {
		return nil, err
	}
	return adapter, nil
}

// newAdapter assembles declarative adapter configuration. Process backend
// selection belongs exclusively to executor.New.
func newAdapter(config Config) (*Adapter, error) {
	if config.BinaryPath == "" {
		return nil, errors.New("create Devin Adapter: binary path is required")
	}
	if config.ExistingHomeDir == "" {
		return nil, errors.New("create Devin Adapter: existing home directory is required")
	}
	adapter := &Adapter{
		binaryPath:      config.BinaryPath,
		existingHomeDir: filepath.Clean(config.ExistingHomeDir),
		runtimeInputs:   append([]string(nil), config.RuntimeInputs...),
	}
	adapter.executor = executor.New()
	registry, binding, workspaceBinding, err := newCategoryRegistry(adapter)
	if err != nil {
		return nil, fmt.Errorf("create Devin Adapter categories: %w", err)
	}
	adapter.categories = registry
	adapter.skillsCategory = binding
	adapter.workspaceCategory = workspaceBinding
	editors, err := newEditorRegistry(adapter)
	if err != nil {
		return nil, fmt.Errorf("create Devin Adapter visual editors: %w", err)
	}
	adapter.editors = editors
	return adapter, nil
}

// Categories returns the fixed ordered Profile Component Categories supported
// by the Devin Adapter.
func (a *Adapter) Categories() *category.Registry {
	return a.categories
}

// PrepareSession creates the synthetic Devin home, copies selected Skill
// Bundles, and preserves only the allowlisted credential file.
// The supplied directory remains caller-owned; unlike Launch, this preparation
// helper does not acquire a Session lease or take responsibility for removal.
func (a *Adapter) PrepareSession(rootDir, workingDirectory string, selected []SkillBundle) (*Session, error) {
	homeDir := filepath.Join(rootDir, "home")
	temporaryDir := filepath.Join(rootDir, "tmp")
	if err := os.MkdirAll(temporaryDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare Devin Session temporary directory: %w", err)
	}
	for _, rule := range devinruntime.GlobalSourceRules() {
		if err := os.MkdirAll(filepath.Join(homeDir, rule.RelativeDirectory), 0o700); err != nil {
			return nil, fmt.Errorf("prepare Devin Session global source %q: %w", rule.Source, err)
		}
	}

	expected := make([]SkillReference, 0, len(selected))
	seen := make(map[SkillReference]struct{}, len(selected))
	for _, bundle := range selected {
		reference, destination, err := bundlePlacement(homeDir, bundle.Reference)
		if err != nil {
			return nil, fmt.Errorf("prepare Devin Session: %w", err)
		}
		identity := diagnosticIdentity(reference)
		if _, exists := seen[reference]; exists {
			return nil, fmt.Errorf("prepare Devin Session: duplicate Skill Reference %q", identity)
		}
		seen[reference] = struct{}{}
		expected = append(expected, reference)

		if err := copyBundle(bundle.BundlePath, destination); err != nil {
			return nil, fmt.Errorf("prepare Devin Session Skill Bundle %q: %w", identity, err)
		}
	}
	devinruntime.SortSkillReferences(expected)

	credentialSource := filepath.Join(a.existingHomeDir, filepath.FromSlash(credentialsRelativePath))
	credentialDestination := filepath.Join(homeDir, filepath.FromSlash(credentialsRelativePath))
	if err := copyCredentialIfPresent(credentialSource, credentialDestination); err != nil {
		return nil, fmt.Errorf("prepare Devin Session authentication allowlist: %w", err)
	}

	return &Session{
		RootDir:          filepath.Clean(rootDir),
		HomeDir:          homeDir,
		TemporaryDir:     temporaryDir,
		SessionsDir:      filepath.Dir(filepath.Clean(rootDir)),
		WorkingDirectory: filepath.Clean(workingDirectory),
		expectedCatalog:  expected,
	}, nil
}

func sourceRule(source GlobalSource) (SourceRule, bool) {
	return devinruntime.SourceRuleFor(source)
}

func cleanBundleRelativePath(path string) (string, error) {
	return devinruntime.CleanBundleRelativePath(path)
}

func diagnosticIdentity(reference SkillReference) string {
	return devinruntime.DiagnosticIdentity(reference)
}

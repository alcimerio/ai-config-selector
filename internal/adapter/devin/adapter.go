// Package devin implements the Devin-specific boundary for ACS Sessions.
package devin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// GlobalSource identifies one explicit Devin user-global Skill Bundle source.
type GlobalSource = skills.Source

const (
	GlobalSourceDevinConfig  GlobalSource = "devin-config"
	GlobalSourceSharedAgents GlobalSource = "shared-agents"
)

// SourceRule records a Devin discovery rule relative to the Session home.
type SourceRule struct {
	Source            GlobalSource
	RelativeDirectory string
}

var globalSourceRules = []SourceRule{
	{Source: GlobalSourceDevinConfig, RelativeDirectory: filepath.Join(".config", "devin", "skills")},
	{Source: GlobalSourceSharedAgents, RelativeDirectory: filepath.Join(".agents", "skills")},
}

var projectSourceDirectories = []string{
	filepath.Join(".devin", "skills"),
	filepath.Join(".agents", "skills"),
}

const credentialsRelativePath = ".local/share/devin/credentials.toml"

// GlobalSourceRules returns the complete set of global Skill Catalog sources
// managed by the Devin Adapter. Project-local sources are deliberately absent.
func GlobalSourceRules() []SourceRule {
	rules := make([]SourceRule, len(globalSourceRules))
	copy(rules, globalSourceRules)
	return rules
}

// ProjectSourceDirectories returns Devin's known repository-local skill roots.
// ACS observes but does not materialize or filter these roots.
func ProjectSourceDirectories() []string {
	directories := make([]string, len(projectSourceDirectories))
	copy(directories, projectSourceDirectories)
	return directories
}

type Config struct {
	BinaryPath      string
	ExistingHomeDir string
	RuntimeInputs   []string
}

type Adapter struct {
	binaryPath      string
	existingHomeDir string
	categories      *category.Registry
	editors         *builder.EditorRegistry
	skillsCategory  category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillsContribution]
	sandbox         launch.ProcessSandbox
	runtimeInputs   []string
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
	lease           *launch.SessionLease
}

func New(config Config) (*Adapter, error) {
	return newAdapter(config, launch.NewProcessSandbox())
}

// newAdapter is the package-private assembly seam. Production callers always
// receive the fail-closed native sandbox from New.
func newAdapter(config Config, sandbox launch.ProcessSandbox) (*Adapter, error) {
	if config.BinaryPath == "" {
		return nil, errors.New("create Devin Adapter: binary path is required")
	}
	if config.ExistingHomeDir == "" {
		return nil, errors.New("create Devin Adapter: existing home directory is required")
	}
	adapter := &Adapter{
		binaryPath:      config.BinaryPath,
		existingHomeDir: filepath.Clean(config.ExistingHomeDir),
		sandbox:         sandbox,
		runtimeInputs:   append([]string(nil), config.RuntimeInputs...),
	}
	if adapter.sandbox == nil {
		return nil, errors.New("create Devin Adapter: process sandbox is required")
	}
	registry, binding, err := newCategoryRegistry(adapter)
	if err != nil {
		return nil, fmt.Errorf("create Devin Adapter categories: %w", err)
	}
	adapter.categories = registry
	adapter.skillsCategory = binding
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
func (a *Adapter) PrepareSession(rootDir, workingDirectory string, selected []SkillBundle) (*Session, error) {
	homeDir := filepath.Join(rootDir, "home")
	temporaryDir := filepath.Join(rootDir, "tmp")
	if err := os.MkdirAll(temporaryDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare Devin Session temporary directory: %w", err)
	}
	for _, rule := range globalSourceRules {
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
	sortSkillReferences(expected)

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

func (a *Adapter) prepareResolvedSession(rootDir, workingDirectory string, resolved category.ResolvedProfile) (*Session, error) {
	homeDir := filepath.Join(rootDir, "home")
	temporaryDir := filepath.Join(rootDir, "tmp")
	if err := os.MkdirAll(temporaryDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare Devin Session temporary directory: %w", err)
	}
	if err := resolved.Materialize(homeDir); err != nil {
		return nil, err
	}
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
	}, nil
}

// Preflight asks the installed Devin CLI to report its observed skills and
// authentication state. It returns only sanitized capability diagnostics.
func (a *Adapter) Preflight(ctx context.Context, session *Session) error {
	if err := a.verifySkillIsolation(ctx, session); err != nil {
		return err
	}
	return a.verifyAuthentication(ctx, session)
}

func (a *Adapter) verifyAuthentication(ctx context.Context, session *Session) error {
	var output bytes.Buffer
	err := a.runSandboxed(ctx, session, []string{"auth", "status"}, launch.Terminal{Output: &output, ErrorOutput: io.Discard})
	if err != nil {
		var sandboxFailure *launch.SandboxError
		if errors.As(err, &sandboxFailure) {
			return err
		}
		return &PreflightError{Capability: CapabilityAuthentication, reason: commandFailureReason(ctx, err, reasonAuthenticationCommandFailed)}
	}
	if !strings.HasPrefix(strings.TrimSpace(output.String()), "Logged in") {
		return &PreflightError{Capability: CapabilityAuthentication, reason: reasonAuthenticationUnavailable}
	}
	return nil
}

func (a *Adapter) verifySkillIsolation(ctx context.Context, session *Session) error {
	observed, failure, err := a.observeGlobalCatalog(ctx, session)
	if err != nil {
		return err
	}
	if failure != 0 {
		return &PreflightError{Capability: CapabilitySkillIsolation, reason: failure}
	}
	if observed.unmanaged || !equalSkillReferences(session.expectedCatalog, observed.managed) {
		return &PreflightError{
			Capability: CapabilitySkillIsolation,
			reason:     reasonCatalogMismatch,
		}
	}

	return nil
}

type observedSkill struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseDir  string `json:"base_dir"`
}

type catalogObservation struct {
	managed   []SkillReference
	unmanaged bool
}

func (a *Adapter) observeGlobalCatalog(ctx context.Context, session *Session) (catalogObservation, preflightFailureReason, error) {
	var stdout bytes.Buffer
	if err := a.runSandboxed(ctx, session, []string{"skills", "list", "--json"}, launch.Terminal{Output: &stdout, ErrorOutput: io.Discard}); err != nil {
		var sandboxFailure *launch.SandboxError
		if errors.As(err, &sandboxFailure) {
			return catalogObservation{}, 0, err
		}
		return catalogObservation{}, commandFailureReason(ctx, err, reasonSkillInspectionCommandFailed), nil
	}

	var skills []observedSkill
	if err := json.Unmarshal(stdout.Bytes(), &skills); err != nil {
		return catalogObservation{}, reasonSkillInspectionOutputInvalid, nil
	}

	projectBundles := discoverProjectBundles(session.WorkingDirectory)
	observed := catalogObservation{managed: make([]SkillReference, 0, len(skills))}
	for _, skill := range skills {
		if skill.Provider == "Builtin" {
			continue
		}
		if projectBundles[filepath.Clean(skill.BaseDir)] {
			continue
		}

		reference, managed := managedReference(session.HomeDir, skill.BaseDir)
		if managed {
			observed.managed = append(observed.managed, reference)
			continue
		}

		// Any non-built-in skill outside the two known project roots is a new
		// global source that ACS cannot safely claim to isolate.
		observed.unmanaged = true
	}
	sortSkillReferences(observed.managed)
	return observed, 0, nil
}

func managedReference(homeDir, baseDir string) (SkillReference, bool) {
	for _, rule := range globalSourceRules {
		root := filepath.Join(homeDir, rule.RelativeDirectory)
		relative, ok := relativeWithin(root, baseDir)
		if ok && relative != "." {
			return SkillReference{Source: rule.Source, RelativePath: relative}, true
		}
	}
	return SkillReference{}, false
}

func discoverProjectBundles(workingDirectory string) map[string]bool {
	bundles := make(map[string]bool)
	for _, relativeRoot := range projectSourceDirectories {
		root := filepath.Join(workingDirectory, relativeRoot)
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			bundlePath := filepath.Join(root, entry.Name())
			bundles[filepath.Clean(bundlePath)] = true
			if resolved, err := filepath.EvalSymlinks(bundlePath); err == nil {
				bundles[filepath.Clean(resolved)] = true
			}
		}
	}
	return bundles
}

func sourceRule(source GlobalSource) (SourceRule, bool) {
	for _, rule := range globalSourceRules {
		if rule.Source == source {
			return rule, true
		}
	}
	return SourceRule{}, false
}

func cleanBundleRelativePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if path == "" || cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid Skill Bundle-relative path %q", path)
	}
	return cleaned, nil
}

func diagnosticIdentity(reference SkillReference) string {
	return escapedDiagnosticIdentity(string(reference.Source) + ":" + filepath.ToSlash(reference.RelativePath))
}

func relativeWithin(root, candidate string) (string, bool) {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func escapedDiagnosticIdentity(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

func equalSkillReferences(left, right []SkillReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortSkillReferences(references []SkillReference) {
	sort.Slice(references, func(left, right int) bool {
		if references[left].Source != references[right].Source {
			return references[left].Source < references[right].Source
		}
		return references[left].RelativePath < references[right].RelativePath
	})
}

func commandFailureReason(ctx context.Context, err error, commandFailed preflightFailureReason) preflightFailureReason {
	if ctx.Err() != nil {
		return reasonVerificationInterrupted
	}
	var executableError *exec.Error
	if errors.As(err, &executableError) || errors.Is(err, os.ErrNotExist) {
		return reasonExecutableUnavailable
	}
	return commandFailed
}

func (a *Adapter) runSandboxed(ctx context.Context, session *Session, arguments []string, terminal launch.Terminal) error {
	process, err := a.sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace: session.WorkingDirectory, SessionsDirectory: session.SessionsDir,
		SessionDirectory: session.RootDir, SessionHome: session.HomeDir,
		TemporaryDirectory: session.TemporaryDir, Executable: a.binaryPath,
		RuntimeInputs: a.runtimeInputs, Arguments: arguments, Terminal: terminal,
	})
	if err != nil {
		return err
	}
	process, err = launch.RetainSessionUntilProcessDone(process, session.lease)
	if err != nil {
		return err
	}
	if err := process.Start(); err != nil {
		return err
	}
	return process.Wait()
}

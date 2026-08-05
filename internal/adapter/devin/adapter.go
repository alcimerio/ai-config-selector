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
	"syscall"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
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
}

type Adapter struct {
	binaryPath      string
	existingHomeDir string
	categories      *category.Registry
	editors         *builder.EditorRegistry
	skillsCategory  category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillsContribution]
}

type SkillBundle = skills.SkillBundle

// SkillReference is the stable source-plus-relative-path identity of one
// selected global Skill Bundle.
type SkillReference = skills.SkillReference

type Session struct {
	RootDir          string
	HomeDir          string
	WorkingDirectory string
	Environment      []string

	expectedCatalog []SkillReference
}

func New(config Config) (*Adapter, error) {
	if config.BinaryPath == "" {
		return nil, errors.New("create Devin Adapter: binary path is required")
	}
	if config.ExistingHomeDir == "" {
		return nil, errors.New("create Devin Adapter: existing home directory is required")
	}
	adapter := &Adapter{
		binaryPath:      config.BinaryPath,
		existingHomeDir: filepath.Clean(config.ExistingHomeDir),
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
		WorkingDirectory: filepath.Clean(workingDirectory),
		Environment:      isolatedEnvironment(homeDir),
		expectedCatalog:  expected,
	}, nil
}

func (a *Adapter) prepareResolvedSession(rootDir, workingDirectory string, resolved category.ResolvedProfile) (*Session, error) {
	homeDir := filepath.Join(rootDir, "home")
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
		WorkingDirectory: filepath.Clean(workingDirectory),
		Environment:      isolatedEnvironment(homeDir),
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
	command := preflightCommand(ctx, a.binaryPath, "auth", "status")
	command.Dir = session.WorkingDirectory
	command.Env = session.Environment
	output, err := command.CombinedOutput()
	if err != nil {
		return &PreflightError{Capability: CapabilityAuthentication, reason: commandFailureReason(ctx, err, reasonAuthenticationCommandFailed)}
	}
	if !strings.HasPrefix(strings.TrimSpace(string(output)), "Logged in") {
		return &PreflightError{Capability: CapabilityAuthentication, reason: reasonAuthenticationUnavailable}
	}
	return nil
}

func (a *Adapter) verifySkillIsolation(ctx context.Context, session *Session) error {
	observed, failure := a.observeGlobalCatalog(ctx, session)
	if failure != 0 {
		return &PreflightError{Capability: CapabilitySkillIsolation, reason: failure}
	}
	if len(observed.unmanaged) != 0 || !equalSkillReferences(session.expectedCatalog, observed.managed) {
		return &PreflightError{
			Capability: CapabilitySkillIsolation,
			Expected:   diagnosticIdentities(session.expectedCatalog, nil),
			Observed:   diagnosticIdentities(observed.managed, observed.unmanaged),
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
	unmanaged []string
}

func (a *Adapter) observeGlobalCatalog(ctx context.Context, session *Session) (catalogObservation, preflightFailureReason) {
	command := preflightCommand(ctx, a.binaryPath, "skills", "list", "--json")
	command.Dir = session.WorkingDirectory
	command.Env = session.Environment
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return catalogObservation{}, commandFailureReason(ctx, err, reasonSkillInspectionCommandFailed)
	}

	var skills []observedSkill
	if err := json.Unmarshal(stdout.Bytes(), &skills); err != nil {
		return catalogObservation{}, reasonSkillInspectionOutputInvalid
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
		observed.unmanaged = append(observed.unmanaged, escapedDiagnosticIdentity("unmanaged:"+skill.Name))
	}
	sortSkillReferences(observed.managed)
	sort.Strings(observed.unmanaged)
	return observed, 0
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

func diagnosticIdentities(references []SkillReference, extra []string) []string {
	identities := make([]string, 0, len(references)+len(extra))
	for _, reference := range references {
		identities = append(identities, diagnosticIdentity(reference))
	}
	identities = append(identities, extra...)
	sort.Strings(identities)
	return identities
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

func preflightCommand(ctx context.Context, binaryPath string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, binaryPath, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	return command
}

func isolatedEnvironment(homeDir string) []string {
	overrides := map[string]string{
		"HOME":            homeDir,
		"XDG_CONFIG_HOME": filepath.Join(homeDir, ".config"),
		"XDG_DATA_HOME":   filepath.Join(homeDir, ".local", "share"),
		"XDG_CACHE_HOME":  filepath.Join(homeDir, ".cache"),
		"XDG_STATE_HOME":  filepath.Join(homeDir, ".local", "state"),
	}

	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := overrides[key]; overridden {
				continue
			}
		}
		environment = append(environment, entry)
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

// Package devinruntime interprets non-executing Devin runtime observations.
//
// It deliberately contains no process, Session, sandbox, callback, or
// credential-payload API. Callers execute probes themselves and pass only their
// completed, redacted-to-be output here for interpretation.
package devinruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// GlobalSource identifies one explicit Devin user-global Skill Bundle source.
type GlobalSource = skills.Source

const (
	GlobalSourceDevinConfig  GlobalSource = "devin-config"
	GlobalSourceSharedAgents GlobalSource = "shared-agents"
)

// SourceRule records a Devin discovery rule relative to the runtime home.
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

// GlobalSourceRules returns the complete set of managed global Skill Catalog
// sources. Project-local sources are deliberately absent.
func GlobalSourceRules() []SourceRule {
	rules := make([]SourceRule, len(globalSourceRules))
	copy(rules, globalSourceRules)
	return rules
}

// ProjectSourceDirectories returns known repository-local skill roots.
func ProjectSourceDirectories() []string {
	directories := make([]string, len(projectSourceDirectories))
	copy(directories, projectSourceDirectories)
	return directories
}

// SourceRuleFor returns the managed global rule for source.
func SourceRuleFor(source GlobalSource) (SourceRule, bool) {
	for _, rule := range globalSourceRules {
		if rule.Source == source {
			return rule, true
		}
	}
	return SourceRule{}, false
}

// CleanBundleRelativePath validates a selected bundle path.
func CleanBundleRelativePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if path == "" || cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid Skill Bundle-relative path %q", path)
	}
	return cleaned, nil
}

// DiagnosticIdentity returns an escaped stable reference identity suitable for
// diagnostics that intentionally name a caller-provided selected reference.
func DiagnosticIdentity(reference skills.SkillReference) string {
	quoted := strconv.QuoteToASCII(string(reference.Source) + ":" + filepath.ToSlash(reference.RelativePath))
	return quoted[1 : len(quoted)-1]
}

// SortSkillReferences orders references by source and relative path.
func SortSkillReferences(references []skills.SkillReference) {
	sort.Slice(references, func(left, right int) bool {
		if references[left].Source != references[right].Source {
			return references[left].Source < references[right].Source
		}
		return references[left].RelativePath < references[right].RelativePath
	})
}

// EqualSkillReferences compares already-normalized reference sequences.
func EqualSkillReferences(left, right []skills.SkillReference) bool {
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

// AuthenticationLoggedIn recognizes the successful Devin auth-status prefix.
func AuthenticationLoggedIn(output []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(output)), "Logged in")
}

// CatalogObservation is the safe result of interpreting a completed skills
// list response. Managed references are canonical source identities; unmanaged
// means a non-built-in skill did not belong to a known project root or managed
// global source.
type CatalogObservation struct {
	managed   []skills.SkillReference
	unmanaged bool
}

// ManagedReferences returns a copy sorted by source and relative path.
func (o CatalogObservation) ManagedReferences() []skills.SkillReference {
	return append([]skills.SkillReference(nil), o.managed...)
}

// HasUnmanagedSource reports whether an unknown global source was observed.
func (o CatalogObservation) HasUnmanagedSource() bool { return o.unmanaged }

type observedSkill struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseDir  string `json:"base_dir"`
}

// InterpretCatalog parses a completed `devin skills list --json` response.
// Built-ins and bundles in the known project roots are excluded. Any other
// unrecognized non-built-in source is reported as unmanaged.
func InterpretCatalog(homeDir, workingDirectory string, output []byte) (CatalogObservation, PreflightFailureReason) {
	var observedSkills []observedSkill
	if err := json.Unmarshal(output, &observedSkills); err != nil {
		return CatalogObservation{}, ReasonSkillInspectionOutputInvalid
	}

	projectBundles := discoverProjectBundles(workingDirectory)
	observed := CatalogObservation{managed: make([]skills.SkillReference, 0, len(observedSkills))}
	for _, skill := range observedSkills {
		if skill.Provider == "Builtin" || projectBundles[filepath.Clean(skill.BaseDir)] {
			continue
		}
		if reference, managed := managedReference(homeDir, skill.BaseDir); managed {
			observed.managed = append(observed.managed, reference)
			continue
		}
		observed.unmanaged = true
	}
	SortSkillReferences(observed.managed)
	return observed, 0
}

func managedReference(homeDir, baseDir string) (skills.SkillReference, bool) {
	resolvedHomeDir, err := filepath.EvalSymlinks(filepath.Clean(homeDir))
	if err != nil {
		return skills.SkillReference{}, false
	}
	resolvedBaseDir, err := filepath.EvalSymlinks(filepath.Clean(baseDir))
	if err != nil {
		return skills.SkillReference{}, false
	}
	for _, rule := range globalSourceRules {
		expectedRoot := filepath.Join(resolvedHomeDir, rule.RelativeDirectory)
		resolvedRoot, err := filepath.EvalSymlinks(expectedRoot)
		if err != nil || resolvedRoot != expectedRoot {
			continue
		}
		relative, ok := relativeWithin(resolvedRoot, resolvedBaseDir)
		if ok && relative != "." {
			return skills.SkillReference{Source: rule.Source, RelativePath: relative}, true
		}
	}
	return skills.SkillReference{}, false
}

func discoverProjectBundles(workingDirectory string) map[string]bool {
	bundles := make(map[string]bool)
	for _, relativeRoot := range projectSourceDirectories {
		entries, err := os.ReadDir(filepath.Join(workingDirectory, relativeRoot))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			bundlePath := filepath.Join(workingDirectory, relativeRoot, entry.Name())
			bundles[filepath.Clean(bundlePath)] = true
			if resolved, err := filepath.EvalSymlinks(bundlePath); err == nil {
				bundles[filepath.Clean(resolved)] = true
			}
		}
	}
	return bundles
}

func relativeWithin(root, candidate string) (string, bool) {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

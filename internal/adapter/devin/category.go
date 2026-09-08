package devin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func NewSkillsProfile(name string, references []skills.SkillReference) profile.Profile {
	selection, err := commonprofile.EncodeSkillSelection(references)
	if err != nil {
		panic(fmt.Sprintf("encode Skills selection: %v", err))
	}
	workspace, _ := json.Marshal(struct {
		Access launch.WorkspaceAccess `json:"access"`
	}{launch.WorkspaceAccessReadOnly})
	paths, _ := json.Marshal(commonprofile.PathSelection{Entries: []commonprofile.PathEntry{}})
	return profile.Profile{Version: profile.CurrentVersion, SourceVersion: profile.CurrentVersion, Name: name,
		Common: map[string]profile.CommonPayload{
			commonprofile.SkillsCapabilityID:    {Version: commonprofile.SkillsCapabilityVersion, Selection: selection},
			commonprofile.WorkspaceCapabilityID: {Version: commonprofile.WorkspaceCapabilityVersion, Selection: workspace},
			commonprofile.PathsCapabilityID:     {Version: commonprofile.PathsCapabilityVersion, Selection: paths},
		}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}}}
}

func SkillReferences(candidate profile.Profile) ([]skills.SkillReference, error) {
	payload, exists := candidate.Categories[commonprofile.SkillsCapabilityID]
	if candidate.Version == profile.CurrentVersion {
		common, commonExists := candidate.Common[commonprofile.SkillsCapabilityID]
		payload, exists = profile.CategoryPayload{SchemaVersion: common.Version, Selection: common.Selection}, commonExists
	}
	if !exists {
		return []skills.SkillReference{}, nil
	}
	if payload.SchemaVersion != commonprofile.SkillsCapabilityVersion {
		return nil, fmt.Errorf("Skills capability uses unsupported version %d", payload.SchemaVersion)
	}
	references, err := commonprofile.DecodeSkillSelection(payload.Selection)
	if err != nil {
		return nil, fmt.Errorf("decode Skills selection: %w", err)
	}
	return references, nil
}

type devinSkillProjection struct{}

func (devinSkillProjection) ID() string   { return "devin" }
func (devinSkillProjection) Version() int { return 1 }
func (devinSkillProjection) Destination(home string, reference skills.SkillReference) (skills.SkillReference, string, error) {
	return bundlePlacement(home, reference)
}
func (devinSkillProjection) Expected(selected []skills.SkillBundle) ([]skills.SkillReference, error) {
	expected := make([]skills.SkillReference, 0, len(selected))
	for _, bundle := range selected {
		reference, _, err := bundlePlacement(filepath.Join("<session>", "home"), bundle.Reference)
		if err != nil {
			return nil, err
		}
		expected = append(expected, reference)
	}
	devinruntime.SortSkillReferences(expected)
	return expected, nil
}
func (devinSkillProjection) Materialize(sessionHome string, selected []skills.SkillBundle) error {
	for _, rule := range devinruntime.GlobalSourceRules() {
		if err := os.MkdirAll(filepath.Join(sessionHome, rule.RelativeDirectory), 0o700); err != nil {
			return fmt.Errorf("prepare Devin Session global source %q: %w", rule.Source, err)
		}
	}
	seen := make(map[skills.SkillReference]struct{}, len(selected))
	for _, bundle := range selected {
		reference, destination, err := bundlePlacement(sessionHome, bundle.Reference)
		if err != nil {
			return err
		}
		if _, exists := seen[reference]; exists {
			return fmt.Errorf("duplicate Skill Reference %q", diagnosticIdentity(reference))
		}
		seen[reference] = struct{}{}
		if err := copyBundle(bundle.BundlePath, destination); err != nil {
			return fmt.Errorf("prepare Devin Session Skill Bundle %q: %w", diagnosticIdentity(reference), err)
		}
	}
	return nil
}

func newCategoryRegistry(adapter *Adapter) (*category.Registry, commonprofile.SkillsBinding, commonprofile.WorkspaceBinding, commonprofile.PathsBinding, error) {
	skillsBinding, err := commonprofile.NewSelectedSkillsBinding(func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
		return DiscoverExactSkillReferences(ctx, adapter.existingHomeDir, references)
	}, devinSkillProjection{})
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, err
	}
	workspaceBinding, err := commonprofile.NewWorkspaceBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, err
	}
	pathsBinding, err := commonprofile.NewPathsBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, err
	}
	registry, err := category.NewRegistryWithRequirements("devin", authority.TargetRequirements{
		Recipe:                  authority.RecipeDevin,
		Executable:              adapter.binaryPath,
		ExecutableRequirementID: "devin-cli",
		RuntimeInputs:           append([]string(nil), adapter.runtimeInputs...),
		RuntimeInputIDs:         append([]string(nil), adapter.runtimeInputIDs...),
		ExistingHomeDirectory:   adapter.existingHomeDir,
		ProtectedPaths:          []string{filepath.Join(adapter.existingHomeDir, ".acs"), filepath.Join(adapter.existingHomeDir, ".codex"), filepath.Join(adapter.existingHomeDir, credentialsRelativePath)},
		ProtectedPathIDs:        []string{"acs-private", "codex-private", "devin-credential"},
		Semantics:               authority.DevinSemantics(),
	}, []category.Registration{skillsBinding.Registration(), workspaceBinding.Registration(), pathsBinding.Registration()}, category.LegacyDecoder{Version: 1, Decode: decodeVersionOneProfile})
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, err
	}
	return registry, skillsBinding, workspaceBinding, pathsBinding, nil
}

func decodeVersionOneProfile(contents []byte) (profile.Profile, error) {
	var legacy struct {
		Version         int             `json:"version"`
		Name            string          `json:"name"`
		Target          string          `json:"target"`
		SkillReferences json.RawMessage `json:"skillReferences"`
	}
	if err := json.Unmarshal(contents, &legacy); err != nil {
		return profile.Profile{}, err
	}
	references, err := commonprofile.DecodeSkillSelection(legacy.SkillReferences)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("decode version-1 skillReferences: %w", err)
	}
	selection, err := commonprofile.EncodeSkillSelection(references)
	if err != nil {
		return profile.Profile{}, err
	}
	return profile.Profile{Version: profile.LegacyCurrentVersion, SourceVersion: 1, Name: legacy.Name, Target: legacy.Target,
		Categories: map[string]profile.CategoryPayload{commonprofile.SkillsCapabilityID: {SchemaVersion: commonprofile.SkillsCapabilityVersion, Selection: selection}}}, nil
}

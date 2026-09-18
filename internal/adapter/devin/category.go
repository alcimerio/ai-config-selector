package devin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
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
	executables, _ := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{}})
	environment, _ := commonprofile.EncodeEnvironmentSelection(commonprofile.EnvironmentSelection{Entries: []commonprofile.EnvironmentEntry{}})
	return profile.Profile{Version: profile.CurrentVersion, SourceVersion: profile.CurrentVersion, Name: name,
		Common: map[string]profile.CommonPayload{
			commonprofile.SkillsCapabilityID:      {Version: commonprofile.SkillsCapabilityVersion, Selection: selection},
			commonprofile.WorkspaceCapabilityID:   {Version: commonprofile.WorkspaceCapabilityVersion, Selection: workspace},
			commonprofile.PathsCapabilityID:       {Version: commonprofile.PathsCapabilityVersion, Selection: paths},
			commonprofile.ExecutablesCapabilityID: {Version: commonprofile.ExecutablesCapabilityVersion, Selection: executables},
			commonprofile.EnvironmentCapabilityID: {Version: commonprofile.EnvironmentCapabilityVersion, Selection: environment},
		}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}}}
}

type devinInstructionProjection struct{}

func (devinInstructionProjection) ID() string   { return "devin" }
func (devinInstructionProjection) Version() int { return 1 }
func (devinInstructionProjection) Expected(selected []instructions.Bundle) ([]instructions.Bundle, error) {
	out := make([]instructions.Bundle, len(selected))
	for i, b := range selected {
		out[i] = instructions.Bundle{Reference: b.Reference, Content: append([]byte(nil), b.Content...)}
	}
	return out, nil
}
func (devinInstructionProjection) Materialize(home string, selected []instructions.Bundle) error {
	dir := filepath.Join(home, ".devin", "rules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("prepare Devin instruction projection")
	}
	seen := map[string]bool{}
	for _, b := range selected {
		name := instructions.DestinationName(b.Reference)
		if seen[name] {
			return errors.New("instruction destination collision")
		}
		seen[name] = true
		dst := filepath.Join(dir, name)
		if _, err := os.Lstat(dst); err == nil {
			return errors.New("instruction destination is already reserved")
		}
		body := append([]byte("---\ntrigger: always_on\n---\n"), b.Content...)
		file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("write Devin instruction projection")
		}
		_, writeErr := file.Write(body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("write Devin instruction projection")
		}
	}
	return nil
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

func newCategoryRegistry(adapter *Adapter) (*category.Registry, commonprofile.SkillsBinding, commonprofile.InstructionsBinding, commonprofile.WorkspaceBinding, commonprofile.PathsBinding, commonprofile.ExecutablesBinding, commonprofile.EnvironmentBinding, error) {
	instructionsBinding, err := commonprofile.NewInstructionsBinding(func(_ context.Context, refs []instructions.Reference) ([]instructions.Bundle, error) {
		return instructions.Resolve(adapter.existingHomeDir, refs)
	}, devinInstructionProjection{})
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	skillsBinding, err := commonprofile.NewSelectedSkillsBinding(func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
		return DiscoverExactSkillReferences(ctx, adapter.existingHomeDir, references)
	}, devinSkillProjection{})
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	workspaceBinding, err := commonprofile.NewWorkspaceBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	pathsBinding, err := commonprofile.NewPathsBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	executablesBinding, err := commonprofile.NewExecutablesBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	environmentBinding, err := commonprofile.NewEnvironmentBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	mcpBinding, err := commonprofile.NewMCPBinding()
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	adapter.mcpCategory = mcpBinding
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
	}, []category.Registration{skillsBinding.Registration(), instructionsBinding.Registration(), workspaceBinding.Registration(), pathsBinding.Registration(), executablesBinding.Registration(), environmentBinding.Registration(), mcpBinding.Registration()}, category.LegacyDecoder{Version: 1, Decode: decodeVersionOneProfile})
	if err != nil {
		return nil, commonprofile.SkillsBinding{}, commonprofile.InstructionsBinding{}, commonprofile.WorkspaceBinding{}, commonprofile.PathsBinding{}, commonprofile.ExecutablesBinding{}, commonprofile.EnvironmentBinding{}, err
	}
	return registry, skillsBinding, instructionsBinding, workspaceBinding, pathsBinding, executablesBinding, environmentBinding, nil
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

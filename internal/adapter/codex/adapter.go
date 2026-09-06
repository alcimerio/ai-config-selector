// Package codex implements the fixed interactive Codex target adapter.
package codex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skillmaterial"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const OverlayVersion = 1

type Config struct {
	BinaryPath      string
	ExistingHomeDir string
	RuntimeInputs   []string
	Executor        codexExecutor
}

type codexExecutor interface {
	ExecuteCodex(context.Context, executor.CodexRequest) (int, error)
}

type Adapter struct {
	home       string
	categories *category.Registry
	editors    *builder.EditorRegistry
	auth       codexExecutor
}

func New(config Config) (*Adapter, error) {
	if config.BinaryPath == "" || config.ExistingHomeDir == "" {
		return nil, errors.New("create Codex Adapter: binary path and existing home are required")
	}
	a := &Adapter{home: filepath.Clean(config.ExistingHomeDir), auth: config.Executor}
	skillsBinding, err := commonprofile.NewSkillsBinding(
		func(ctx context.Context) ([]skills.SkillBundle, error) {
			return devin.DiscoverCommonSkillCatalog(ctx, a.home)
		},
		codexSkillProjection{},
	)
	if err != nil {
		return nil, err
	}
	workspaceBinding, err := commonprofile.NewWorkspaceBinding()
	if err != nil {
		return nil, err
	}
	a.categories, err = category.NewRegistryWithRequirements("codex", authority.TargetRequirements{
		Recipe: authority.RecipeCodex, Executable: config.BinaryPath, RuntimeInputs: append([]string(nil), config.RuntimeInputs...),
	}, []category.Registration{skillsBinding.Registration(), workspaceBinding.Registration()})
	if err != nil {
		return nil, err
	}
	skillsEditor, err := builder.RegisterSkillsEditor(skillsBinding, func(ctx context.Context) ([]skills.SkillBundle, error) {
		return devin.DiscoverCommonSkillCatalog(ctx, a.home)
	})
	if err != nil {
		return nil, err
	}
	workspaceEditor, err := builder.RegisterWorkspaceEditor(workspaceBinding)
	if err != nil {
		return nil, err
	}
	a.editors, err = builder.NewEditorRegistry(a.categories, skillsEditor, workspaceEditor)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Adapter) Categories() *category.Registry { return a.categories }

func (a *Adapter) BuildProfile(ctx context.Context, name string, draft category.Draft, save builder.SaveFunc, input io.Reader, output io.Writer) (builder.Outcome, error) {
	model, err := builder.NewModel(name, draft, a.editors)
	if err != nil {
		return builder.Outcome{}, err
	}
	return builder.Run(ctx, model.WithSaver(save), input, output)
}

func (a *Adapter) ResolveAuth(resolved category.ResolvedProfile, override string) (category.ResolvedProfile, error) {
	if resolved.Requirements().Recipe != authority.RecipeCodex || resolved.Overlay() != "codex" {
		return category.ResolvedProfile{}, errors.New("resolved authority does not select Codex")
	}
	effective := resolved.AuthRef()
	if override != "" {
		effective = override
	}
	if _, err := codexauth.ParseCredentialRef(effective); err != nil {
		return category.ResolvedProfile{}, err
	}
	return resolved.WithAuthRef(effective), nil
}

func (a *Adapter) PlanLaunch(ctx context.Context, workingDirectory string, resolved category.ResolvedProfile, override string) (launch.Plan, error) {
	if resolved.Requirements().Recipe != authority.RecipeCodex || resolved.Overlay() != "codex" {
		return launch.Plan{}, errors.New("resolved authority does not select Codex")
	}
	effective := resolved.AuthRef()
	if override != "" {
		effective = override
	}
	if effective != "" {
		if _, err := codexauth.ParseCredentialRef(effective); err != nil {
			return launch.Plan{}, err
		}
	}
	return resolved.WithAuthRef(effective).Plan(ctx, workingDirectory)
}

func (a *Adapter) Launch(ctx context.Context, _ string, _ string, resolved category.ResolvedProfile, override string, terminal launch.Terminal) (int, error) {
	if a.auth == nil {
		return 1, errors.New("interactive Codex executor is unavailable")
	}
	selected, err := a.ResolveAuth(resolved, override)
	if err != nil {
		return 1, err
	}
	return a.auth.ExecuteCodex(ctx, executor.CodexRequest{ResolvedPlan: &selected, Terminal: terminal})
}

func NewProfile(name, authRef string, common profile.Profile) (profile.Profile, error) {
	if authRef != "" {
		if _, err := codexauth.ParseCredentialRef(authRef); err != nil {
			return profile.Profile{}, err
		}
	}
	common.Name = name
	if common.Overlays == nil {
		common.Overlays = map[string]profile.OverlayPayload{}
	}
	common.Overlays["codex"] = profile.OverlayPayload{Version: OverlayVersion, AuthRef: authRef}
	return common, nil
}

type codexSkillProjection struct{}

func (codexSkillProjection) ID() string   { return "codex" }
func (codexSkillProjection) Version() int { return 1 }
func (codexSkillProjection) Expected(selected []skills.SkillBundle) ([]skills.SkillReference, error) {
	result := make([]skills.SkillReference, 0, len(selected))
	for _, bundle := range selected {
		result = append(result, bundle.Reference)
	}
	return result, nil
}
func (codexSkillProjection) Destination(home string, reference skills.SkillReference) (skills.SkillReference, string, error) {
	if err := commonprofile.ValidateCommonDestinations([]skills.SkillBundle{{Reference: reference}}); err != nil {
		return skills.SkillReference{}, "", err
	}
	return reference, filepath.Join(home, ".codex", "skills", string(reference.Source), filepath.Clean(reference.RelativePath)), nil
}
func (projection codexSkillProjection) Materialize(home string, selected []skills.SkillBundle) error {
	seen := map[string]skills.SkillReference{}
	for _, bundle := range selected {
		reference, destination, err := projection.Destination(home, bundle.Reference)
		if err != nil {
			return err
		}
		key := filepath.Clean(destination)
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("Codex Skill projection collision between %q and %q", previous, reference)
		}
		seen[key] = reference
		if err := skillmaterial.CopyBundle(bundle.BundlePath, destination); err != nil {
			return fmt.Errorf("project Codex Skill %s:%s: %w", reference.Source, reference.RelativePath, err)
		}
	}
	return nil
}

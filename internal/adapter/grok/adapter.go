// Package grok implements the fixed interactive Grok Build target adapter.
package grok

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/grokcompat"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
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
	RuntimeInputIDs []string
}

type grokExecutor interface {
	Readiness(context.Context) (launch.SandboxReadiness, error)
	RunGrok(context.Context, executor.GrokRequest) (int, error)
}

type Adapter struct {
	home       string
	categories *category.Registry
	editors    *builder.EditorRegistry
	executor   grokExecutor
	mcp        commonprofile.MCPBinding
}

func New(config Config) (*Adapter, error) {
	if config.BinaryPath == "" || config.ExistingHomeDir == "" {
		return nil, errors.New("create Grok Adapter: binary path and existing home are required")
	}
	if len(config.RuntimeInputIDs) != len(config.RuntimeInputs) {
		return nil, errors.New("create Grok Adapter: every runtime input requires a stable semantic ID")
	}
	adapter := &Adapter{home: filepath.Clean(config.ExistingHomeDir), executor: executor.New()}
	bindings, err := commonprofile.NewBindings(commonprofile.Runtime{
		DiscoverSkills: func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
			return devin.DiscoverExactSkillReferences(ctx, adapter.home, references)
		},
		SkillProjection: grokSkillProjection{},
		ResolveInstructions: func(_ context.Context, refs []instructions.Reference) ([]instructions.Bundle, error) {
			return instructions.Resolve(adapter.home, refs)
		},
		InstructionProjection: grokInstructionProjection{},
	})
	if err != nil {
		return nil, err
	}
	adapter.mcp = bindings.MCP
	adapter.categories, err = category.NewRegistryWithRequirements("grok", authority.TargetRequirements{
		Recipe: authority.RecipeGrok, Executable: config.BinaryPath, ExecutableRequirementID: grokcompat.ExecutableRequirementID,
		RuntimeInputs: append([]string(nil), config.RuntimeInputs...), RuntimeInputIDs: append([]string(nil), config.RuntimeInputIDs...),
		ExistingHomeDirectory: adapter.home,
		ProtectedPaths: []string{
			filepath.Join(adapter.home, ".acs"), filepath.Join(adapter.home, ".grok"), filepath.Join(adapter.home, ".codex"),
			filepath.Join(adapter.home, ".local", "share", "devin", "credentials.toml"),
		},
		ProtectedPathIDs: []string{"acs-private", "grok-private", "codex-private", "devin-credential"},
		Semantics:        authority.GrokSemantics(),
	}, bindings.Registrations())
	if err != nil {
		return nil, err
	}
	skillsEditor, err := builder.RegisterSkillsEditor(bindings.Skills, func(ctx context.Context) ([]skills.SkillBundle, error) {
		return devin.DiscoverCommonSkillCatalog(ctx, adapter.home)
	})
	if err != nil {
		return nil, err
	}
	workspaceEditor, err := builder.RegisterWorkspaceEditor(bindings.Workspace)
	if err != nil {
		return nil, err
	}
	instructionsEditor, err := builder.RegisterInstructionsEditor(bindings.Instructions, func(context.Context) ([]instructions.Bundle, error) {
		return instructions.Discover(adapter.home)
	})
	if err != nil {
		return nil, err
	}
	pathsEditor, err := builder.RegisterPathsEditor(bindings.Paths)
	if err != nil {
		return nil, err
	}
	exclusionsEditor, err := builder.RegisterExclusionsEditor(bindings.Exclusions)
	if err != nil {
		return nil, err
	}
	executablesEditor, err := builder.RegisterExecutablesEditor(bindings.Executables)
	if err != nil {
		return nil, err
	}
	environmentEditor, err := builder.RegisterEnvironmentEditor(bindings.Environment)
	if err != nil {
		return nil, err
	}
	mcpEditor, err := builder.RegisterMCPEditor(bindings.MCP)
	if err != nil {
		return nil, err
	}
	networkEditor, err := builder.RegisterNetworkEditor(bindings.Network)
	if err != nil {
		return nil, err
	}
	adapter.editors, err = builder.NewEditorRegistry(adapter.categories, skillsEditor, instructionsEditor, workspaceEditor, pathsEditor, exclusionsEditor, executablesEditor, environmentEditor, mcpEditor, networkEditor)
	if err != nil {
		return nil, err
	}
	return adapter, nil
}

func (a *Adapter) Categories() *category.Registry { return a.categories }

func (a *Adapter) SetMCPSelection(draft *category.Draft, selection commonprofile.MCPSelection) error {
	return category.SetSelection(draft, a.mcp, selection)
}

func (a *Adapter) BuildProfile(ctx context.Context, name string, draft category.Draft, save builder.SaveFunc, input io.Reader, output io.Writer) (builder.Outcome, error) {
	model, err := builder.NewModel(name, draft, a.editors)
	if err != nil {
		return builder.Outcome{}, err
	}
	return builder.Run(ctx, model.WithSaver(save), input, output)
}

func (a *Adapter) PlanLaunch(ctx context.Context, _ string, workingDirectory string, resolved category.ResolvedProfile) (launch.Plan, error) {
	if resolved.Requirements().Recipe != authority.RecipeGrok || resolved.Overlay() != "grok" {
		return launch.Plan{}, errors.New("resolved authority does not select Grok")
	}
	plan, err := resolved.Plan(ctx, workingDirectory)
	if err != nil {
		return launch.Plan{}, err
	}
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Grok project scope:", Items: []launch.PlanItem{
		{Label: "Repository .grok/skills, AGENTS.md, and .grok/rules stay inactive unless the operator accepts Grok's folder-trust prompt."},
		{Label: "ACS does not copy host trust, managed configuration, or pass --trust."},
		{Label: "Authentication copies only ~/.grok/auth.json when present, or uses a selected XAI_API_KEY. No login is started inside the sandbox."},
	}})
	readiness, err := a.executor.Readiness(ctx)
	if err != nil {
		return launch.Plan{}, fmt.Errorf("inspect required process sandbox readiness: %w", err)
	}
	plan.Sections = append(plan.Sections, grokReadinessSection(readiness))
	return plan, nil
}

func grokReadinessSection(readiness launch.SandboxReadiness) launch.PlanSection {
	platformResult := "unsupported"
	if readiness.Supported {
		platformResult = "supported"
	}
	backendResult := "not ready"
	if readiness.Ready {
		backendResult = "ready"
	} else if readiness.Failure != nil {
		backendResult += " (" + readiness.Failure.Error() + ")"
	}
	return launch.PlanSection{Title: "Sandbox readiness:", Items: []launch.PlanItem{
		{Label: "required sandbox mode: " + readiness.RequiredMode},
		{Label: "selected native backend: " + readiness.Backend},
		{Label: "supported platform: " + platformResult + " (" + readiness.Platform + ")"},
		{Label: "backend readiness: " + backendResult},
		{Label: "ACS will not start Grok without the required sandbox."},
	}}
}

func (a *Adapter) Launch(ctx context.Context, sessionsDirectory, workingDirectory string, resolved category.ResolvedProfile, terminal launch.Terminal) (int, error) {
	if a.executor == nil {
		return 1, errors.New("interactive Grok executor is unavailable")
	}
	exitCode, err := a.executor.RunGrok(ctx, executor.GrokRequest{
		SessionsDirectory: sessionsDirectory, WorkingDirectory: workingDirectory, ResolvedPlan: &resolved, Terminal: terminal,
	})
	if err != nil {
		return exitCode, sanitizeLaunchError(err)
	}
	return exitCode, nil
}

func sanitizeLaunchError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	var exit interface {
		error
		ExitCode() int
	}
	if errors.As(err, &exit) {
		return &ExitError{Code: exit.ExitCode()}
	}
	switch {
	case errors.Is(err, executor.ErrGrokUnsupportedVersion), errors.Is(err, executor.ErrGrokAuthenticationUnavailable), errors.Is(err, executor.ErrGrokControlEnvironment):
		return err
	case errors.Is(err, executor.ErrEnvironmentUnavailable), errors.Is(err, executor.ErrEnvironmentInvalid), errors.Is(err, executor.ErrEnvironmentTooLarge):
		return err
	}
	return &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "Grok exited" }
func (e *ExitError) ExitCode() int { return e.Code }

type grokInstructionProjection struct{}

func (grokInstructionProjection) ID() string   { return "grok" }
func (grokInstructionProjection) Version() int { return 1 }
func (grokInstructionProjection) Expected(selected []instructions.Bundle) ([]instructions.Bundle, error) {
	return selected, nil
}
func (grokInstructionProjection) Materialize(home string, selected []instructions.Bundle) error {
	dir := filepath.Join(home, ".grok", "rules")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("prepare Grok instruction projection")
	}
	seen := map[string]bool{}
	for _, bundle := range selected {
		name := instructions.DestinationName(bundle.Reference)
		if seen[name] {
			return errors.New("instruction destination collision")
		}
		seen[name] = true
		destination := filepath.Join(dir, name)
		if _, err := os.Lstat(destination); err == nil {
			return errors.New("instruction destination is already reserved")
		}
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("write Grok instruction projection")
		}
		_, writeErr := file.Write(bundle.Content)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("write Grok instruction projection")
		}
	}
	return nil
}

type grokSkillProjection struct{}

func (grokSkillProjection) ID() string   { return "grok" }
func (grokSkillProjection) Version() int { return 1 }
func (grokSkillProjection) Expected(selected []skills.SkillBundle) ([]skills.SkillReference, error) {
	result := make([]skills.SkillReference, 0, len(selected))
	for _, bundle := range selected {
		result = append(result, bundle.Reference)
	}
	return result, nil
}
func (grokSkillProjection) Destination(home string, reference skills.SkillReference) (skills.SkillReference, string, error) {
	if err := commonprofile.ValidateCommonDestinations([]skills.SkillBundle{{Reference: reference}}); err != nil {
		return skills.SkillReference{}, "", err
	}
	return reference, filepath.Join(home, ".grok", "skills", string(reference.Source), filepath.Clean(reference.RelativePath)), nil
}
func (projection grokSkillProjection) Materialize(home string, selected []skills.SkillBundle) error {
	seen := map[string]skills.SkillReference{}
	for _, bundle := range selected {
		reference, destination, err := projection.Destination(home, bundle.Reference)
		if err != nil {
			return err
		}
		key := filepath.Clean(destination)
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("Grok Skill projection collision between %q and %q", previous, reference)
		}
		seen[key] = reference
		if err := skillmaterial.CopyBundle(bundle.BundlePath, destination); err != nil {
			return fmt.Errorf("project Grok Skill %s:%s: %w", reference.Source, reference.RelativePath, err)
		}
	}
	return nil
}

func NewProfile(name string, common profile.Profile) profile.Profile {
	common.Name = name
	if common.Overlays == nil {
		common.Overlays = map[string]profile.OverlayPayload{}
	}
	common.Overlays["grok"] = profile.OverlayPayload{Version: OverlayVersion}
	return common
}

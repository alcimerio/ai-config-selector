package commonprofile

import (
	"context"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// Runtime supplies only the target-specific discovery and material projection
// needed by active bindings. Passive codecs require none of these dependencies.
type Runtime struct {
	DiscoverSkills        func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error)
	SkillProjection       SkillProjection
	ResolveInstructions   func(context.Context, []instructions.Reference) ([]instructions.Bundle, error)
	InstructionProjection InstructionProjection
}

// Bindings keeps the typed editor handles and the fixed common registration
// order in one place, shared by passive codecs and target adapters.
type Bindings struct {
	Skills       SkillsBinding
	Instructions InstructionsBinding
	Workspace    WorkspaceBinding
	Exclusions   ExclusionsBinding
	Paths        PathsBinding
	Executables  ExecutablesBinding
	Environment  EnvironmentBinding
	MCP          MCPBinding
}

func (bindings Bindings) Registrations() []category.Registration {
	return []category.Registration{
		bindings.Skills.Registration(), bindings.Instructions.Registration(),
		bindings.Workspace.Registration(), bindings.Paths.Registration(), bindings.Exclusions.Registration(),
		bindings.Executables.Registration(), bindings.Environment.Registration(),
		bindings.MCP.Registration(),
	}
}

// NewBindings assembles active common capabilities with explicit runtime
// dependencies. The target adapter retains its execution requirements/editors.
func NewBindings(runtime Runtime) (Bindings, error) {
	instructions, err := NewInstructionsBinding(runtime.ResolveInstructions, runtime.InstructionProjection)
	if err != nil {
		return Bindings{}, err
	}
	skills, err := NewSelectedSkillsBinding(runtime.DiscoverSkills, runtime.SkillProjection)
	if err != nil {
		return Bindings{}, err
	}
	return newBindings(skills, instructions)
}

func newBindings(skills SkillsBinding, instructions InstructionsBinding) (Bindings, error) {
	bindings := Bindings{Skills: skills, Instructions: instructions}
	var err error
	if bindings.Workspace, err = NewWorkspaceBinding(); err != nil {
		return Bindings{}, err
	}
	if bindings.Paths, err = NewPathsBinding(); err != nil {
		return Bindings{}, err
	}
	if bindings.Exclusions, err = NewExclusionsBinding(); err != nil {
		return Bindings{}, err
	}
	if bindings.Executables, err = NewExecutablesBinding(); err != nil {
		return Bindings{}, err
	}
	if bindings.Environment, err = NewEnvironmentBinding(); err != nil {
		return Bindings{}, err
	}
	if bindings.MCP, err = NewMCPBinding(); err != nil {
		return Bindings{}, err
	}
	return bindings, nil
}

// NewCodec composes strict Profile codecs without a target adapter, user home,
// resource discovery, editors, execution requirements, or launch authority.
func NewCodec() (*category.Codec, error) {
	skills, err := category.BindCodec(skillsDefinition())
	if err != nil {
		return nil, err
	}
	instructions, err := category.BindCodec(instructionsDefinition())
	if err != nil {
		return nil, err
	}
	bindings, err := newBindings(skills, instructions)
	if err != nil {
		return nil, err
	}
	return category.NewCodec(bindings.Registrations())
}

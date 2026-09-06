// Package authority owns the immutable resolved plan shared by explanation,
// materialization, executor checks, probes, and attached target execution.
package authority

import (
	"context"
	"fmt"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type Contribution struct {
	ID    string
	Value launch.Contribution
}

type Recipe string

const (
	RecipeShell Recipe = "shell"
	RecipeDevin Recipe = "devin"
	RecipeCodex Recipe = "codex"
)

// TargetRequirements are registered once during application assembly. They
// are intrinsic target inputs, not per-launch adapter authority, and are never
// rendered by the sanitized explanation.
type TargetRequirements struct {
	Recipe                Recipe
	Executable            string
	RuntimeInputs         []string
	ExistingHomeDirectory string
}

type Plan struct {
	contributions   []Contribution
	workspaceAccess launch.WorkspaceAccess
	sourceVersion   int
	overlay         string
	requirements    TargetRequirements
	authRef         string
}

func New(contributions []Contribution, workspaceAccess launch.WorkspaceAccess, sourceVersion int, overlay string, supplied ...TargetRequirements) Plan {
	requirements := TargetRequirements{Recipe: RecipeShell}
	if overlay != "" {
		requirements.Recipe = RecipeDevin
	}
	if len(supplied) != 0 {
		requirements = supplied[0]
		requirements.RuntimeInputs = append([]string(nil), requirements.RuntimeInputs...)
	}
	return Plan{contributions: append([]Contribution(nil), contributions...), workspaceAccess: workspaceAccess, sourceVersion: sourceVersion, overlay: overlay, requirements: requirements}
}
func (plan Plan) WorkspaceAccess() launch.WorkspaceAccess {
	if plan.workspaceAccess == "" {
		return launch.WorkspaceAccessReadWrite
	}
	return plan.workspaceAccess
}
func (plan Plan) SourceVersion() int { return plan.sourceVersion }
func (plan Plan) Overlay() string    { return plan.overlay }
func (plan Plan) AuthRef() string    { return plan.authRef }

// WithAuthRef returns an independent resolved plan with one canonical opaque
// authentication reference. Validation belongs to the target adapter.
func (plan Plan) WithAuthRef(value string) Plan { plan.authRef = value; return plan }
func (plan Plan) Requirements() TargetRequirements {
	result := plan.requirements
	result.RuntimeInputs = append([]string(nil), result.RuntimeInputs...)
	return result
}

func (plan Plan) DevinExpectedCatalog() []skills.SkillReference {
	for _, entry := range plan.contributions {
		if expected, ok := entry.Value.(interface {
			DevinExpectedCatalog() []skills.SkillReference
		}); ok {
			return append([]skills.SkillReference(nil), expected.DevinExpectedCatalog()...)
		}
	}
	return nil
}

func (plan Plan) CodexExpectedCatalog() []skills.SkillReference {
	for _, entry := range plan.contributions {
		if expected, ok := entry.Value.(interface {
			CodexExpectedCatalog() []skills.SkillReference
		}); ok {
			return append([]skills.SkillReference(nil), expected.CodexExpectedCatalog()...)
		}
	}
	return nil
}

func (plan Plan) Plan(ctx context.Context, workingDirectory string) (launch.Plan, error) {
	provenance := fmt.Sprintf("Profile envelope v%d", plan.sourceVersion)
	if plan.sourceVersion < 3 {
		provenance += " legacy compatibility"
	} else {
		provenance += " common workspace v1"
	}
	explanation := launch.Plan{Sections: []launch.PlanSection{{
		Title: "Resolved execution authority:",
		Items: []launch.PlanItem{
			{Label: "recipe", Details: []launch.PlanDetail{{Label: "selected", Value: string(plan.requirements.Recipe)}}},
			{Label: "workspace", Details: []launch.PlanDetail{{Label: "access", Value: string(plan.WorkspaceAccess())}, {Label: "source", Value: provenance}}},
			{Label: "Session", Details: []launch.PlanDetail{{Label: "access", Value: "private and writable"}}},
			{Label: "intrinsic target/runtime inputs", Details: []launch.PlanDetail{{Label: "authority", Value: "registered by ACS"}}},
		},
	}}}
	if plan.requirements.Recipe == RecipeCodex {
		reference := plan.authRef
		if reference == "" {
			reference = "(required at launch)"
		}
		explanation.Sections[0].Items = append(explanation.Sections[0].Items,
			launch.PlanItem{Label: "authentication", Details: []launch.PlanDetail{{Label: "reference", Value: reference}, {Label: "existence/status", Value: "unchecked"}}})
	}
	for _, entry := range plan.contributions {
		var err error
		if resolved, ok := entry.Value.(interface {
			PlanResolved(context.Context, string, int, string, *launch.Plan) error
		}); ok {
			err = resolved.PlanResolved(ctx, workingDirectory, plan.sourceVersion, plan.overlay, &explanation)
		} else {
			err = entry.Value.Plan(ctx, workingDirectory, &explanation)
		}
		if err != nil {
			return launch.Plan{}, fmt.Errorf("plan %s capability: %w", entry.ID, err)
		}
	}
	return explanation, nil
}

func (plan Plan) Materialize(sessionHome string) error {
	for _, entry := range plan.contributions {
		var err error
		if resolved, ok := entry.Value.(interface {
			MaterializeResolved(string, int, string) error
		}); ok {
			err = resolved.MaterializeResolved(sessionHome, plan.sourceVersion, plan.overlay)
		} else {
			err = entry.Value.Materialize(sessionHome)
		}
		if err != nil {
			return fmt.Errorf("materialize %s capability: %w", entry.ID, err)
		}
	}
	return nil
}

func (plan Plan) Verify(ctx context.Context, verification launch.VerificationContext) error {
	for _, entry := range plan.contributions {
		if err := entry.Value.Verify(ctx, verification); err != nil {
			return fmt.Errorf("verify %s capability: %w", entry.ID, err)
		}
	}
	return nil
}

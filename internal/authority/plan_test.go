package authority

import (
	"context"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPlanOwnsImmutableRequirementsAndSanitizedAuthorityExplanation(t *testing.T) {
	requirements := TargetRequirements{
		Recipe: RecipeDevin, Executable: "/private/target", RuntimeInputs: []string{"/private/runtime"}, ExistingHomeDirectory: "/private/home",
	}
	plan := New(nil, launch.WorkspaceAccessReadOnly, 3, "devin", requirements)
	requirements.RuntimeInputs[0] = "/changed"

	resolved := plan.Requirements()
	resolved.RuntimeInputs[0] = "/also-changed"
	if got := plan.Requirements().RuntimeInputs[0]; got != "/private/runtime" {
		t.Fatalf("plan requirements were mutable: %q", got)
	}
	explanation, err := plan.Plan(context.Background(), "/private/workspace")
	if err != nil {
		t.Fatal(err)
	}
	if len(explanation.Sections) != 1 || explanation.Sections[0].Title != "Resolved execution authority:" {
		t.Fatalf("authority explanation = %#v", explanation)
	}
	for _, item := range explanation.Sections[0].Items {
		for _, detail := range item.Details {
			if detail.Value == "/private/target" || detail.Value == "/private/runtime" || detail.Value == "/private/home" || detail.Value == "/private/workspace" {
				t.Fatalf("explanation exposed intrinsic path: %#v", explanation)
			}
		}
	}
}

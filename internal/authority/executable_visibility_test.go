package authority

import (
	"context"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type executableFactsContribution struct {
	intents []launch.ExecutableGrantIntent
}

func (executableFactsContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (executableFactsContribution) Materialize(string) error                         { return nil }
func (executableFactsContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (value executableFactsContribution) ExecutableGrantIntents() []launch.ExecutableGrantIntent {
	return append([]launch.ExecutableGrantIntent(nil), value.intents...)
}

func executableVisibilityPlan(intents []launch.ExecutableGrantIntent) Plan {
	return New([]Contribution{{ID: "executables", Value: executableFactsContribution{intents: intents}}}, launch.WorkspaceAccessReadOnly, 3, "")
}

func TestExecutableVisibilityExplanationDistinguishesCoverageAndNonExclusiveRuntime(t *testing.T) {
	plan := executableVisibilityPlan([]launch.ExecutableGrantIntent{
		{ID: "workspace", ReferenceKind: launch.ExecutableReferenceWorkspaceRelative, Path: "bin/tool"},
		{ID: "fixed", ReferenceKind: launch.ExecutableReferenceFixedSearchName, Name: "git"},
		{ID: "local", ReferenceKind: launch.ExecutableReferenceLocalAbsolute, Path: "/private/machine/tool"},
	})
	explanation := plan.Explanation()
	workspace := factByID(t, explanation.Requested, "common.executables.workspace")
	if workspace.Reason != "stored_v3_intent_covered_by_workspace_read" || workspace.Value.LogicalReference != "bin/tool" {
		t.Fatalf("workspace requested fact = %#v", workspace)
	}
	for _, fact := range explanation.Effective {
		if fact.ID == "executable.workspace" {
			t.Fatal("workspace-covered executable was emitted as an independent effective grant")
		}
	}
	if factByID(t, explanation.Effective, "executable.fixed").Value.LogicalReference != "git" {
		t.Fatal("fixed-search logical name missing")
	}
	if got := factByID(t, explanation.Effective, "executable.local").Value.LogicalReference; got != "" {
		t.Fatalf("private local binding leaked: %q", got)
	}
	if factByID(t, explanation.Effective, "runtime.executable-visibility").Value.Mode != "non-exclusive-intrinsic-readable" {
		t.Fatal("intrinsic executable visibility fact missing")
	}
	if factByID(t, explanation.Unsupported, "unsupported.exclusive-execution-filtering").Value.Mode != "non-exclusive-visibility-only" {
		t.Fatal("non-exclusive limitation missing")
	}
}

func TestExecutableVisibilityDigestTracksLogicalIntentNotPrivateBindingAndOwnsCopies(t *testing.T) {
	baseIntents := []launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceFixedSearchName, Name: "git"}}
	base := executableVisibilityPlan(baseIntents)
	baseIntents[0].Name = "mutated"
	if base.AuthorityDigest() != executableVisibilityPlan([]launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceFixedSearchName, Name: "git"}}).AuthorityDigest() {
		t.Fatal("caller mutation changed captured authority")
	}
	changedName := executableVisibilityPlan([]launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceFixedSearchName, Name: "sh"}})
	changedPath := executableVisibilityPlan([]launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceWorkspaceRelative, Path: "bin/tool"}})
	localOne := executableVisibilityPlan([]launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceLocalAbsolute, Path: "/one/tool"}})
	localTwo := executableVisibilityPlan([]launch.ExecutableGrantIntent{{ID: "tool", ReferenceKind: launch.ExecutableReferenceLocalAbsolute, Path: "/two/tool"}})
	if base.AuthorityDigest() == changedName.AuthorityDigest() || base.AuthorityDigest() == changedPath.AuthorityDigest() {
		t.Fatal("logical executable semantic change did not alter digest")
	}
	if localOne.AuthorityDigest() != localTwo.AuthorityDigest() {
		t.Fatal("private local executable binding changed digest")
	}
}

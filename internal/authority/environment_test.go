package authority

import (
	"context"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type environmentFactContribution struct{ intents []launch.EnvironmentIntent }

func (environmentFactContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (environmentFactContribution) Materialize(string) error                         { return nil }
func (environmentFactContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (value environmentFactContribution) EnvironmentIntents() []launch.EnvironmentIntent {
	return append([]launch.EnvironmentIntent(nil), value.intents...)
}

func TestEnvironmentSemanticDigestExcludesPrivateBindingAndPreservesEmptyBaseline(t *testing.T) {
	baseline := New(nil, launch.WorkspaceAccessReadOnly, 3, "")
	empty := New([]Contribution{{ID: "environment", Value: environmentFactContribution{intents: []launch.EnvironmentIntent{}}}}, launch.WorkspaceAccessReadOnly, 3, "")
	if baseline.AuthorityDigest() != empty.AuthorityDigest() {
		t.Fatalf("empty environment changed baseline digest: %s != %s", baseline.AuthorityDigest(), empty.AuthorityDigest())
	}
	intent := launch.EnvironmentIntent{ID: "token", Destination: "TOOL_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference", Provider: "host-environment", Reference: "PRIVATE_A", Required: true, Classification: "secret"}
	plan := New([]Contribution{{ID: "environment", Value: environmentFactContribution{intents: []launch.EnvironmentIntent{intent}}}}, launch.WorkspaceAccessReadOnly, 3, "")
	intent.Reference = "PRIVATE_B"
	rebound := New([]Contribution{{ID: "environment", Value: environmentFactContribution{intents: []launch.EnvironmentIntent{intent}}}}, launch.WorkspaceAccessReadOnly, 3, "")
	if plan.AuthorityDigest() != rebound.AuthorityDigest() {
		t.Fatal("private secret reference changed semantic digest")
	}
	for name, mutate := range map[string]func(*launch.EnvironmentIntent){
		"destination":    func(value *launch.EnvironmentIntent) { value.Destination = "OTHER_TOKEN" },
		"scope":          func(value *launch.EnvironmentIntent) { value.Scope = "future-scope" },
		"source kind":    func(value *launch.EnvironmentIntent) { value.SourceKind = "host-environment" },
		"provider":       func(value *launch.EnvironmentIntent) { value.Provider = "future-provider" },
		"classification": func(value *launch.EnvironmentIntent) { value.Classification = "non-secret" },
		"required":       func(value *launch.EnvironmentIntent) { value.Required = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := intent
			mutate(&changed)
			other := New([]Contribution{{ID: "environment", Value: environmentFactContribution{intents: []launch.EnvironmentIntent{changed}}}}, launch.WorkspaceAccessReadOnly, 3, "")
			if plan.AuthorityDigest() == other.AuthorityDigest() {
				t.Fatalf("%s mutation did not change digest", name)
			}
		})
	}
	returned := plan.EnvironmentIntents()
	returned[0].Destination = "MUTATED"
	explanation := plan.Explanation()
	*explanation.Requested[0].Value.Required = false
	if plan.EnvironmentIntents()[0].Destination != "TOOL_TOKEN" || !*plan.Explanation().Requested[0].Value.Required {
		t.Fatal("returned environment values mutated plan authority")
	}
}

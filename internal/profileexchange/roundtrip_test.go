package profileexchange_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
)

func TestRoundTripProducesEquivalentCommonAndTargetPlans(t *testing.T) {
	references, _ := json.Marshal([]map[string]string{{"source": "shared-agents", "relativePath": "review"}})
	original := profile.Profile{Version: 3, SourceVersion: 3, Name: "original", Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: references}, "workspace": {Version: 1, Selection: json.RawMessage(`{"access":"read-write"}`)},
	}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}, "codex": {Version: 1, AuthRef: "work"}}}
	document, _, err := profileexchange.Export(original)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"work"}}`)
	result := profileexchange.Decode(document, bindings, "imported")
	if result.Candidate == nil {
		t.Fatalf("decode = %#v", result)
	}

	devinTarget, err := devin.New(devin.Config{BinaryPath: "/target/devin", ExistingHomeDir: "/home/example"})
	if err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "/target/codex", ExistingHomeDir: "/home/example"})
	if err != nil {
		t.Fatal(err)
	}
	comparePlan(t, devinTarget.Categories(), original, *result.Candidate, "")
	comparePlan(t, devinTarget.Categories(), original, *result.Candidate, "devin")
	comparePlan(t, codexTarget.Categories(), original, *result.Candidate, "codex")
}

func comparePlan(t *testing.T, registry interface {
	ResolveSyntaxFor(context.Context, profile.Profile, string) (category.ResolvedProfile, error)
}, before, after profile.Profile, overlay string) {
	t.Helper()
	left, err := registry.ResolveSyntaxFor(context.Background(), before, overlay)
	if err != nil {
		t.Fatal(err)
	}
	right, err := registry.ResolveSyntaxFor(context.Background(), after, overlay)
	if err != nil {
		t.Fatal(err)
	}
	leftPlan, err := left.Plan(context.Background(), "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	rightPlan, err := right.Plan(context.Background(), "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftPlan, rightPlan) {
		t.Fatalf("%q plans differ:\n%#v\n%#v", overlay, leftPlan, rightPlan)
	}
}

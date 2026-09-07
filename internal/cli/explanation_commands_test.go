package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type explanationBoundContribution struct {
	Facts       int `json:"facts"`
	StringBytes int `json:"stringBytes"`
}

func (explanationBoundContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (explanationBoundContribution) Materialize(string) error                         { return nil }
func (explanationBoundContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (contribution explanationBoundContribution) SemanticFacts(int, string) authority.Facts {
	facts := make([]authority.Fact, contribution.Facts)
	for index := range facts {
		facts[index] = authority.Fact{ID: "synthetic-bound", Kind: "test", Value: authority.FactValue{Mode: strings.Repeat("x", contribution.StringBytes)}, Reason: "public_bound", Source: authority.FactSource{Kind: "test", ID: "registered"}}
	}
	return authority.Facts{Requested: facts}
}

func TestExplanationGrammarAcceptsReorderedIntentSpecificFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"explain", "sandbox", "--json", "--profile", "example", "--check-native-readiness"},
		{"explain", "devin", "--check-native-readiness", "--profile", "example", "--json"},
		{"explain", "codex", "--json", "--auth", "work", "--profile", "example", "--check-native-readiness"},
		{"explain", "run", "--json", "--profile", "example", "--check-native-readiness", "--", "/usr/bin/true", "--json"},
	} {
		if _, problem := parseCommand(arguments); problem != "" {
			t.Errorf("parse %q: %s", arguments, problem)
		}
	}
}

func TestInactiveUnknownOverlaysAreDeterministicOpaqueAndOutsideDigest(t *testing.T) {
	baseline := authority.Explanation{AuthorityDigest: "sha256:unchanged"}
	first, second := baseline, baseline
	firstProfile := profile.Profile{Overlays: map[string]profile.OverlayPayload{
		"PRIVATE-KEY-B": {Version: 41},
		"PRIVATE-KEY-A": {Version: 99},
	}}
	secondProfile := profile.Profile{Overlays: map[string]profile.OverlayPayload{
		"PRIVATE-KEY-A": {Version: 99},
		"PRIVATE-KEY-B": {Version: 41},
	}}
	appendInactiveOverlays(&first, firstProfile, "devin")
	appendInactiveOverlays(&second, secondProfile, "devin")
	if first.AuthorityDigest != baseline.AuthorityDigest || second.AuthorityDigest != baseline.AuthorityDigest {
		t.Fatal("presentation-only inactive overlays changed semantic digest")
	}
	if !reflect.DeepEqual(first.Unsupported, second.Unsupported) || len(first.Unsupported) != 2 {
		t.Fatalf("unknown overlay rendering is not deterministic and one-per-overlay: first=%#v second=%#v", first.Unsupported, second.Unsupported)
	}
	encoded, err := json.Marshal(first.Unsupported)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE-KEY-A", "PRIVATE-KEY-B", `"version":41`, `"version":99`} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatalf("unknown overlay key or payload escaped through presentation: %s", encoded)
		}
	}
	for _, fact := range first.Unsupported {
		if fact.Reason != "inactive_overlay_unknown_presentation_only_excluded_from_digest" || fact.Value.Mode != "opaque-inert" || fact.Source.ID != "unknown-overlay" {
			t.Fatalf("unknown overlay fact is not a sanitized limitation: %#v", fact)
		}
	}
}

func TestExplanationGrammarRejectsCrossIntentAndDigestFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"explain", "sandbox", "--profile", "example", "--auth", "work"},
		{"explain", "devin", "--profile", "example", "--expect-authority-digest", "sha256:" + strings.Repeat("0", 64)},
		{"explain", "codex", "--profile", "example", "--", "/usr/bin/true"},
		{"explain", "run", "--profile", "example", "/usr/bin/true"},
		{"sandbox", "--profile", "example", "--json"},
		{"run", "--profile", "example", "--check-native-readiness", "--", "/usr/bin/true"},
		{"devin", "--profile", "example", "--expect-authority-digest", "sha256:" + strings.Repeat("A", 64)},
	} {
		if _, problem := parseCommand(arguments); problem == "" {
			t.Errorf("accepted invalid grammar %q", arguments)
		}
	}
}

func TestExplainRunHelpDocumentsLiteralBoundaryWithoutDependencies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := App{Output: &stdout, ErrorOutput: &stderr}
	if handled, code := app.RunInformational([]string{"explain", "run", "--help"}); !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, stderr.String())
	}
	for _, marker := range []string{"one required -- boundary", "one literal child argv", "--check-native-readiness", "--json"} {
		if !strings.Contains(stdout.String(), marker) {
			t.Errorf("help omitted %q: %s", marker, stdout.String())
		}
	}
}

func TestExplanationBoundsAreByteBasedAndInclusiveOnlyAtDeclaredMaximum(t *testing.T) {
	maximumString := strings.Repeat("x", maximumExplanationStringBytes)
	maximumFacts := make([]authority.Fact, maximumExplanationFacts)
	for index := range maximumFacts {
		maximumFacts[index] = authority.Fact{ID: "fact", Kind: "kind", Reason: "reason", Source: authority.FactSource{Kind: "source", ID: "id"}, Value: authority.FactValue{Mode: "mode"}}
	}
	maximumChecks := make([]explanationCheck, maximumExplanationChecks)
	for index := range maximumChecks {
		maximumChecks[index] = explanationCheck{ID: "check", Status: "unchecked", Code: "code", Detail: "detail"}
	}
	if !explanationWithinBounds(authority.Explanation{Requested: maximumFacts}, maximumChecks) {
		t.Fatal("declared exact fact/check maxima were rejected")
	}
	if !explanationWithinBounds(authority.Explanation{Requested: []authority.Fact{{ID: maximumString}}}, nil) {
		t.Fatal("declared exact string byte maximum was rejected")
	}
	if explanationWithinBounds(authority.Explanation{Requested: append(maximumFacts, authority.Fact{})}, nil) {
		t.Fatal("fact count above declared maximum was accepted")
	}
	if explanationWithinBounds(authority.Explanation{}, append(maximumChecks, explanationCheck{})) {
		t.Fatal("check count above declared maximum was accepted")
	}
	if explanationWithinBounds(authority.Explanation{Requested: []authority.Fact{{ID: maximumString + "x"}}}, nil) {
		t.Fatal("string above declared byte maximum was accepted")
	}
	if explanationWithinBounds(authority.Explanation{Requested: []authority.Fact{{ID: strings.Repeat("é", maximumExplanationStringBytes/2) + "x"}}}, nil) {
		t.Fatal("multibyte string above declared byte maximum was accepted")
	}
}

func TestExplanationTooLargeDiagnosticContainsNoPartialPlanOrDigest(t *testing.T) {
	var output bytes.Buffer
	app := App{Output: &output}
	invocation := invocation{enabled: true, value: "example", command: commandSpec{path: "explain devin"}}
	if code := app.writeExplanationDiagnostic(invocation, "explanation_too_large", "The semantic explanation exceeds a declared format bound."); code != 1 {
		t.Fatalf("diagnostic exit = %d", code)
	}
	if !strings.Contains(output.String(), `"plan":null`) || !strings.Contains(output.String(), `"code":"explanation_too_large"`) || strings.Contains(output.String(), "authorityDigest") {
		t.Fatalf("oversized diagnostic exposed a partial plan: %s", output.String())
	}
}

func TestExplanationPublicCommandRejectsSemanticAndEncodedOutputBoundsWithoutPartialPlan(t *testing.T) {
	for _, test := range []struct {
		name        string
		selection   explanationBoundContribution
		wantMessage string
	}{
		{name: "fact count", selection: explanationBoundContribution{Facts: maximumExplanationFacts + 1, StringBytes: 1}, wantMessage: "declared format bound"},
		{name: "string bytes", selection: explanationBoundContribution{Facts: 1, StringBytes: maximumExplanationStringBytes + 1}, wantMessage: "declared format bound"},
		{name: "encoded bytes", selection: explanationBoundContribution{Facts: 300, StringBytes: maximumExplanationStringBytes}, wantMessage: "output-size bound"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, err := category.Bind(category.Definition[explanationBoundContribution, explanationBoundContribution, explanationBoundContribution]{
				ID: "test-bound", SchemaVersion: 1,
				Empty: func() explanationBoundContribution { return explanationBoundContribution{} },
				Resolve: func(_ context.Context, selection explanationBoundContribution) (explanationBoundContribution, error) {
					return selection, nil
				},
				Contribute: func(selection explanationBoundContribution) (explanationBoundContribution, error) {
					return selection, nil
				},
				Count: func(selection explanationBoundContribution) int { return selection.Facts },
			})
			if err != nil {
				t.Fatal(err)
			}
			registry, err := category.NewRegistry("devin", binding.Registration())
			if err != nil {
				t.Fatal(err)
			}
			draft := registry.NewDraft()
			if err := category.SetSelection(&draft, binding, test.selection); err != nil {
				t.Fatal(err)
			}
			candidate, err := registry.NewProfile("bounded", draft)
			if err != nil {
				t.Fatal(err)
			}
			store := profile.NewStore(t.TempDir(), registry)
			if _, err := store.Create(candidate); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			app := App{Categories: registry, Profiles: store, WorkingDirectory: t.TempDir(), Output: &output, ErrorOutput: &output}
			if code := app.Run(context.Background(), []string{"explain", "sandbox", "--profile", "bounded", "--json"}); code != 1 {
				t.Fatalf("exit = %d, output=%s", code, output.String())
			}
			if !strings.Contains(output.String(), `"plan":null`) || !strings.Contains(output.String(), `"code":"explanation_too_large"`) || !strings.Contains(output.String(), test.wantMessage) || strings.Contains(output.String(), "authorityDigest") || strings.Contains(output.String(), strings.Repeat("x", 64)) {
				t.Fatalf("public bound failure exposed a partial result: %s", output.String())
			}
		})
	}
}

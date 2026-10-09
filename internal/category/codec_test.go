package category

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type codecTestContribution struct{}

func (codecTestContribution) Plan(context.Context, string, *launch.Plan) error         { return nil }
func (codecTestContribution) Materialize(string) error                                 { return nil }
func (codecTestContribution) Verify(context.Context, launch.VerificationContext) error { return nil }

func TestCodecRequiresNoRuntimeAndCannotSupplyExecutionBindings(t *testing.T) {
	definition := Definition[[]string, []string, codecTestContribution]{
		ID: "texts", SchemaVersion: 1, Optional: true,
		Empty: func() []string { return []string{} }, Count: func(values []string) int { return len(values) },
	}
	if _, err := Bind(definition); err == nil {
		t.Fatal("execution binding accepted missing runtime dependencies")
	}
	binding, err := BindCodec(definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry("devin", binding.Registration()); err == nil || !strings.Contains(err.Error(), "codec-only") {
		t.Fatalf("execution registry accepted codec-only binding: %v", err)
	}
	codec, err := NewCodec([]Registration{binding.Registration()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode([]byte(`{"version":3,"name":"example","common":{}}`))
	if err != nil || string(got.Common["texts"].Selection) != `[]` {
		t.Fatalf("passive defaults: %+v, %v", got, err)
	}
	if !reflect.DeepEqual(codec.registry.requirements, authority.TargetRequirements{}) {
		t.Fatal("passive codec contains execution requirements")
	}
	for _, registration := range codec.registry.ordered {
		if registration.resolve != nil || registration.resolveSyntax != nil || registration.contribute != nil {
			t.Fatal("passive codec contains a runtime callback")
		}
	}
	if _, executable := any(codec).(interface {
		Resolve(context.Context, profile.Profile) (ResolvedProfile, error)
	}); executable {
		t.Fatal("passive codec exposes runtime resolution")
	}
}

func TestCodecPreservesValidationWithoutCallingRuntime(t *testing.T) {
	checks := 0
	binding, err := Bind(Definition[[]string, []string, codecTestContribution]{
		ID: "texts", SchemaVersion: 1,
		Empty: func() []string { return []string{} }, Count: func(values []string) int { return len(values) },
		Resolve: func(context.Context, []string) ([]string, error) {
			t.Fatal("codec resolved resources")
			return nil, nil
		},
		ResolveSyntax: func([]string) ([]string, error) { t.Fatal("codec resolved syntax authority"); return nil, nil },
		Contribute: func([]string) (codecTestContribution, error) {
			t.Fatal("codec constructed launch authority")
			return codecTestContribution{}, nil
		},
		ValidateReferences: func(values []string, selections map[string]any) error {
			checks++
			if !reflect.DeepEqual(values, selections["texts"]) {
				t.Fatal("cross-capability validation lost selections")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewCodec([]Registration{binding.Registration()})
	if err != nil {
		t.Fatal(err)
	}
	candidate := profile.Profile{Version: profile.CurrentVersion, Name: "example", Common: map[string]profile.CommonPayload{
		"texts": {Version: 1, Selection: json.RawMessage(`["selected"]`)},
	}}
	_, canonical, err := profile.Canonicalize(codec, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.DecodeNamed("example", canonical); err != nil {
		t.Fatal(err)
	}
	if checks == 0 {
		t.Fatal("codec skipped cross-capability validation")
	}
	if binding.registration.resolve == nil || binding.registration.contribute == nil {
		t.Fatal("passive construction mutated the active binding")
	}
}

func TestCodecRejectsInvalidComposition(t *testing.T) {
	binding, err := BindCodec(Definition[[]string, []string, codecTestContribution]{ID: "texts", SchemaVersion: 1,
		Empty: func() []string { return []string{} }, Count: func(values []string) int { return len(values) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		registrations []Registration
	}{
		{name: "missing registrations"},
		{name: "invalid registration", registrations: []Registration{{}}},
		{name: "duplicate registration", registrations: []Registration{binding.Registration(), binding.Registration()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCodec(test.registrations); err == nil {
				t.Fatal("invalid composition admitted")
			}
		})
	}
}

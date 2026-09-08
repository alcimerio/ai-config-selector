package commonprofile

import (
	"context"
	"encoding/json"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

const (
	EnvironmentCapabilityID      = "environment"
	EnvironmentCapabilityVersion = 1
)

type EnvironmentSource = environmentintent.Source
type EnvironmentEntry = environmentintent.Entry
type EnvironmentSelection = environmentintent.Selection

type EnvironmentContribution struct{ entries []launch.EnvironmentIntent }

func (EnvironmentContribution) Plan(context.Context, string, *launch.Plan) error         { return nil }
func (EnvironmentContribution) Materialize(string) error                                 { return nil }
func (EnvironmentContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (EnvironmentContribution) SemanticFacts(int, string) authority.Facts                { return authority.Facts{} }
func (value EnvironmentContribution) EnvironmentIntents() []launch.EnvironmentIntent {
	return append([]launch.EnvironmentIntent(nil), value.entries...)
}

type EnvironmentBinding = category.Binding[EnvironmentSelection, EnvironmentSelection, EnvironmentContribution]

func NewEnvironmentBinding() (EnvironmentBinding, error) {
	return category.Bind(category.Definition[EnvironmentSelection, EnvironmentSelection, EnvironmentContribution]{
		ID: EnvironmentCapabilityID, SchemaVersion: EnvironmentCapabilityVersion,
		Empty: environmentintent.Empty, LegacyEmpty: environmentintent.Empty,
		Encode: environmentintent.Encode, Decode: environmentintent.Decode,
		Resolve: func(_ context.Context, selection EnvironmentSelection) (EnvironmentSelection, error) {
			return environmentintent.Canonical(selection)
		},
		ResolveSyntax: environmentintent.Canonical,
		Contribute: func(selection EnvironmentSelection) (EnvironmentContribution, error) {
			intents := make([]launch.EnvironmentIntent, 0, len(selection.Entries))
			for _, entry := range selection.Entries {
				intents = append(intents, launch.EnvironmentIntent{ID: entry.ID, Destination: entry.Destination, Scope: entry.Scope, SourceKind: entry.Source.Kind, SourceName: entry.Source.Name, Provider: entry.Source.Provider, Reference: entry.Source.Reference, Required: entry.Required, Classification: entry.Classification})
			}
			return EnvironmentContribution{entries: intents}, nil
		},
		Count: func(selection EnvironmentSelection) int { return len(selection.Entries) },
	})
}

func DecodeEnvironmentSelection(data json.RawMessage) (EnvironmentSelection, error) {
	return environmentintent.Decode(data)
}

func EncodeEnvironmentSelection(selection EnvironmentSelection) (json.RawMessage, error) {
	return environmentintent.Encode(selection)
}

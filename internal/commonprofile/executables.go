package commonprofile

import (
	"context"
	"encoding/json"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

const (
	ExecutablesCapabilityID      = "executables"
	ExecutablesCapabilityVersion = 1
)

type ExecutableReference = executableintent.Reference
type ExecutableEntry = executableintent.Entry
type ExecutableSelection = executableintent.Selection

type ExecutableContribution struct {
	entries []launch.ExecutableGrantIntent
}

func (ExecutableContribution) Plan(context.Context, string, *launch.Plan) error         { return nil }
func (ExecutableContribution) Materialize(string) error                                 { return nil }
func (ExecutableContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (value ExecutableContribution) ExecutableGrantIntents() []launch.ExecutableGrantIntent {
	return append([]launch.ExecutableGrantIntent(nil), value.entries...)
}
func (ExecutableContribution) SemanticFacts(int, string) authority.Facts { return authority.Facts{} }

type ExecutablesBinding = category.Binding[ExecutableSelection, ExecutableSelection, ExecutableContribution]

func NewExecutablesBinding() (ExecutablesBinding, error) {
	return category.Bind(category.Definition[ExecutableSelection, ExecutableSelection, ExecutableContribution]{
		ID: ExecutablesCapabilityID, SchemaVersion: ExecutablesCapabilityVersion,
		Empty: executableintent.Empty, LegacyEmpty: executableintent.Empty,
		Encode: executableintent.Encode, Decode: executableintent.Decode,
		Resolve: func(_ context.Context, selection ExecutableSelection) (ExecutableSelection, error) {
			return executableintent.Canonical(selection)
		},
		ResolveSyntax: executableintent.Canonical,
		Contribute: func(selection ExecutableSelection) (ExecutableContribution, error) {
			intents := make([]launch.ExecutableGrantIntent, 0, len(selection.Entries))
			for _, entry := range selection.Entries {
				intents = append(intents, launch.ExecutableGrantIntent{ID: entry.ID, ReferenceKind: launch.ExecutableReferenceKind(entry.Reference.Kind), Name: entry.Reference.Name, Path: entry.Reference.Path})
			}
			return ExecutableContribution{entries: intents}, nil
		},
		Count: func(selection ExecutableSelection) int { return len(selection.Entries) },
	})
}

func DecodeExecutableSelection(data json.RawMessage) (ExecutableSelection, error) {
	return executableintent.Decode(data)
}
func EncodeExecutableSelection(selection ExecutableSelection) (json.RawMessage, error) {
	return executableintent.Encode(selection)
}

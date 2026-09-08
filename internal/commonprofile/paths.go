package commonprofile

import (
	"context"
	"encoding/json"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
)

const (
	PathsCapabilityID      = "paths"
	PathsCapabilityVersion = 1
)

type PathReference = pathintent.Reference
type PathEntry = pathintent.Entry
type PathSelection = pathintent.Selection

type PathContribution struct{ entries []launch.PathGrantIntent }

func (PathContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (PathContribution) Materialize(string) error                         { return nil }
func (PathContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (contribution PathContribution) PathGrantIntents() []launch.PathGrantIntent {
	return append([]launch.PathGrantIntent(nil), contribution.entries...)
}
func (PathContribution) SemanticFacts(int, string) authority.Facts { return authority.Facts{} }

type PathsBinding = category.Binding[PathSelection, PathSelection, PathContribution]

func NewPathsBinding() (PathsBinding, error) {
	return category.Bind(category.Definition[PathSelection, PathSelection, PathContribution]{
		ID: PathsCapabilityID, SchemaVersion: PathsCapabilityVersion,
		Empty:       pathintent.Empty,
		LegacyEmpty: pathintent.Empty,
		Encode:      encodePathSelection,
		Decode:      decodePathSelection,
		Resolve: func(_ context.Context, selection PathSelection) (PathSelection, error) {
			return pathintent.Canonical(selection)
		},
		ResolveSyntax: pathintent.Canonical,
		Contribute: func(selection PathSelection) (PathContribution, error) {
			intents := make([]launch.PathGrantIntent, 0, len(selection.Entries))
			for _, entry := range selection.Entries {
				intents = append(intents, launch.PathGrantIntent{ID: entry.ID, Access: entry.Access, Type: entry.Type, ReferenceKind: launch.PathReferenceKind(entry.Reference.Kind), Path: entry.Reference.Path})
			}
			return PathContribution{entries: intents}, nil
		},
		Count: func(selection PathSelection) int { return len(selection.Entries) },
	})
}

func encodePathSelection(selection PathSelection) (json.RawMessage, error) {
	return pathintent.Encode(selection)
}

func decodePathSelection(data json.RawMessage) (PathSelection, error) {
	return pathintent.Decode(data)
}

// DecodePathSelection validates a serialized paths capability.  It is exported
// for mutation flows that must preserve only currently trusted local bindings.
func DecodePathSelection(data json.RawMessage) (PathSelection, error) {
	return decodePathSelection(data)
}

// EncodePathSelection canonicalizes and serializes a paths capability.
func EncodePathSelection(selection PathSelection) (json.RawMessage, error) {
	return encodePathSelection(selection)
}

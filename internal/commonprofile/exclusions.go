package commonprofile

import (
	"context"
	"encoding/json"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/exclusionintent"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

const (
	ExclusionsCapabilityID      = "exclusions"
	ExclusionsCapabilityVersion = 1
	// ExclusionWarningsTitle heads advisory output for redundant entries.
	ExclusionWarningsTitle = "Exclusion warnings (Profile kept as stored; every entry is still enforced):"
)

type ExclusionReference = exclusionintent.Reference
type ExclusionEntry = exclusionintent.Entry
type ExclusionSelection = exclusionintent.Selection

type ExclusionContribution struct {
	entries  []launch.PathExclusionIntent
	warnings []string
}

// ExclusionWarnings describes redundant entries (nested under a directory entry
// or differing only by letter case). They are advisory: the selection stays
// valid and every entry is still enforced.
func ExclusionWarnings(selection ExclusionSelection) []string {
	advisories := exclusionintent.Advisories(selection)
	if len(advisories) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(advisories))
	for _, advisory := range advisories {
		warnings = append(warnings, advisory.String())
	}
	return warnings
}

func (contribution ExclusionContribution) Plan(ctx context.Context, _ string, plan *launch.Plan) error {
	if len(contribution.entries) == 0 {
		return nil
	}
	section := launch.PlanSection{Title: "Excluded filesystem paths:"}
	for _, entry := range contribution.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		details := []launch.PlanDetail{{Label: "type", Value: string(entry.Type)}, {Label: "reference", Value: string(entry.ReferenceKind)}, {Label: "access", Value: "denied"}}
		if entry.ReferenceKind == launch.PathReferenceWorkspaceRelative {
			details = append(details, launch.PlanDetail{Label: "path", Value: entry.Path})
		}
		section.Items = append(section.Items, launch.PlanItem{Label: entry.ID, Details: details})
	}
	plan.Sections = append(plan.Sections, section)
	if len(contribution.warnings) != 0 {
		warnings := launch.PlanSection{Title: ExclusionWarningsTitle}
		for _, warning := range contribution.warnings {
			warnings.Items = append(warnings.Items, launch.PlanItem{Label: warning})
		}
		plan.Sections = append(plan.Sections, warnings)
	}
	return nil
}
func (ExclusionContribution) Materialize(string) error { return nil }
func (ExclusionContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (contribution ExclusionContribution) PathExclusionIntents() []launch.PathExclusionIntent {
	return append([]launch.PathExclusionIntent(nil), contribution.entries...)
}
func (ExclusionContribution) SemanticFacts(string) authority.Facts { return authority.Facts{} }

type ExclusionsBinding = category.Binding[ExclusionSelection, ExclusionSelection, ExclusionContribution]

func NewExclusionsBinding() (ExclusionsBinding, error) {
	return category.Bind(category.Definition[ExclusionSelection, ExclusionSelection, ExclusionContribution]{
		ID: ExclusionsCapabilityID, SchemaVersion: ExclusionsCapabilityVersion,
		Empty:    exclusionintent.Empty,
		Optional: true,
		Encode:   EncodeExclusionSelection,
		Decode:   DecodeExclusionSelection,
		Resolve: func(_ context.Context, selection ExclusionSelection) (ExclusionSelection, error) {
			return exclusionintent.Canonical(selection)
		},
		ResolveSyntax: exclusionintent.Canonical,
		Contribute: func(selection ExclusionSelection) (ExclusionContribution, error) {
			intents := make([]launch.PathExclusionIntent, 0, len(selection.Entries))
			for _, entry := range selection.Entries {
				intents = append(intents, launch.PathExclusionIntent{ID: entry.ID, Type: launch.PathType(entry.Type), ReferenceKind: launch.PathReferenceKind(entry.Reference.Kind), Path: entry.Reference.Path})
			}
			return ExclusionContribution{entries: intents, warnings: ExclusionWarnings(selection)}, nil
		},
		Count: func(selection ExclusionSelection) int { return len(selection.Entries) },
	})
}

func EncodeExclusionSelection(selection ExclusionSelection) (json.RawMessage, error) {
	return exclusionintent.Encode(selection)
}

func DecodeExclusionSelection(data json.RawMessage) (ExclusionSelection, error) {
	return exclusionintent.Decode(data)
}

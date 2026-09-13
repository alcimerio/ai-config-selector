package commonprofile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

const InstructionsCapabilityID = "instructions"
const InstructionsCapabilityVersion = 1

type InstructionProjection interface {
	ID() string
	Version() int
	Expected([]instructions.Bundle) ([]instructions.Bundle, error)
	Materialize(string, []instructions.Bundle) error
}
type InstructionsContribution struct {
	selected   []instructions.Bundle
	projection InstructionProjection
}
type InstructionsBinding = category.Binding[[]instructions.Reference, []instructions.Bundle, InstructionsContribution]

func NewInstructionsBinding(resolve func(context.Context, []instructions.Reference) ([]instructions.Bundle, error), projection InstructionProjection) (InstructionsBinding, error) {
	if resolve == nil || projection == nil || projection.ID() == "" || projection.Version() < 1 {
		return InstructionsBinding{}, errors.New("common instructions registration is incomplete")
	}
	return category.Bind(category.Definition[[]instructions.Reference, []instructions.Bundle, InstructionsContribution]{
		ID: InstructionsCapabilityID, SchemaVersion: InstructionsCapabilityVersion,
		Empty: func() []instructions.Reference { return []instructions.Reference{} }, LegacyEmpty: func() []instructions.Reference { return []instructions.Reference{} },
		Encode: instructions.Encode, Decode: instructions.Decode,
		Resolve: func(ctx context.Context, refs []instructions.Reference) ([]instructions.Bundle, error) {
			return resolve(ctx, refs)
		},
		ResolveSyntax: func(refs []instructions.Reference) ([]instructions.Bundle, error) {
			bundles := make([]instructions.Bundle, len(refs))
			for i, ref := range refs {
				bundles[i].Reference = ref
			}
			return bundles, nil
		},
		Contribute: func(selected []instructions.Bundle) (InstructionsContribution, error) {
			selected = append([]instructions.Bundle(nil), selected...)
			seen := map[string]bool{}
			for i := range selected {
				name := instructions.DestinationName(selected[i].Reference)
				if seen[name] {
					return InstructionsContribution{}, errors.New("instruction target destination collision")
				}
				seen[name] = true
				selected[i].Content = append([]byte(nil), selected[i].Content...)
			}
			return InstructionsContribution{selected: selected, projection: projection}, nil
		},
		Count: func(refs []instructions.Reference) int { return len(refs) },
	})
}

func (c InstructionsContribution) Plan(ctx context.Context, _ string, plan *launch.Plan) error {
	return c.PlanResolved(ctx, "", profile.CurrentVersion, c.projection.ID(), plan)
}
func (c InstructionsContribution) PlanResolved(ctx context.Context, _ string, sourceVersion int, overlay string, plan *launch.Plan) error {
	if len(c.selected) == 0 {
		return nil
	}
	section := launch.PlanSection{Title: "Selected common instruction bundles:"}
	for _, item := range c.selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		logical := filepath.ToSlash(filepath.Join("session-home/.acs/common/v1/instructions", item.Reference.Source, item.Reference.RelativePath))
		details := []launch.PlanDetail{{Label: "identity", Value: item.Reference.Source + ":" + item.Reference.RelativePath}, {Label: "common", Value: logical}}
		if overlay == "devin" && c.projection.ID() == "devin" {
			details = append(details, launch.PlanDetail{Label: "target projection", Value: "session-home/.devin/rules/" + instructions.DestinationName(item.Reference)})
		}
		section.Items = append(section.Items, launch.PlanItem{Label: filepath.Base(item.Reference.RelativePath), Details: details})
	}
	plan.Sections = append(plan.Sections, section)
	return nil
}
func (c InstructionsContribution) Materialize(home string) error {
	return c.MaterializeResolved(home, profile.CurrentVersion, c.projection.ID())
}
func (c InstructionsContribution) MaterializeResolved(home string, sourceVersion int, overlay string) error {
	for _, item := range c.selected {
		dst := filepath.Join(home, ".acs", "common", "v1", "instructions", item.Reference.Source, filepath.FromSlash(item.Reference.RelativePath))
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return errors.New("prepare common instruction directory")
		}
		if err := os.WriteFile(dst, item.Content, 0600); err != nil {
			return errors.New("write common instruction material")
		}
	}
	if overlay == c.projection.ID() {
		return c.projection.Materialize(home, c.selected)
	}
	return nil
}
func (InstructionsContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (c InstructionsContribution) DevinInstructionBundles() []instructions.Bundle {
	out := make([]instructions.Bundle, len(c.selected))
	for i, v := range c.selected {
		out[i] = instructions.Bundle{Reference: v.Reference, Content: append([]byte(nil), v.Content...)}
	}
	return out
}
func (c InstructionsContribution) SemanticFacts(sourceVersion int, overlay string) authority.Facts {
	if len(c.selected) == 0 {
		return authority.Facts{}
	}
	f := authority.Facts{Requested: []authority.Fact{{ID: "common.instructions", Kind: "capability", Value: authority.FactValue{Mode: "selected-exact-identities"}, Reason: "stored_selection", Source: authority.FactSource{Kind: "profile", ID: InstructionsCapabilityID, Version: InstructionsCapabilityVersion}}}}
	if overlay == "devin" && c.projection.ID() == "devin" && len(c.selected) > 0 {
		f.TargetAdded = append(f.TargetAdded, authority.Fact{ID: "instructions.target-projection", Kind: "target-projection", Value: authority.FactValue{Mode: "selected-always-on-rules"}, Reason: "registered_projection", Source: authority.FactSource{Kind: "target", ID: c.projection.ID(), Version: c.projection.Version()}})
	}
	for _, v := range c.selected {
		id := v.Reference.Source + ":" + v.Reference.RelativePath
		ident := &authority.SkillIdentity{Source: v.Reference.Source, RelativePath: v.Reference.RelativePath}
		f.Requested = append(f.Requested, authority.Fact{ID: "instructions.selected." + id, Kind: "instruction", Value: authority.FactValue{Identity: ident}, Reason: "stored_selection", Source: authority.FactSource{Kind: "profile", ID: InstructionsCapabilityID, Version: InstructionsCapabilityVersion}})
		f.Effective = append(f.Effective, authority.Fact{ID: "instructions.common." + id, Kind: "material", Value: authority.FactValue{Identity: ident, LogicalLocation: "session-home/common-instructions"}, Reason: "selected_common_material", Source: authority.FactSource{Kind: "profile", ID: InstructionsCapabilityID, Version: InstructionsCapabilityVersion}})
	}
	return f
}
func (c InstructionsContribution) Expected() ([]instructions.Bundle, error) {
	return c.projection.Expected(c.selected)
}
func (c InstructionsContribution) String() string {
	return fmt.Sprintf("%d selected instruction bundles", len(c.selected))
}

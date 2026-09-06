package commonprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skillmaterial"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"golang.org/x/text/unicode/norm"
)

const SkillsCapabilityID = "skills"
const SkillsCapabilityVersion = 1

// SkillProjection is one fixed, registered target mapping. It can map and copy
// selected common materials, but cannot choose a backend, process, Session,
// workspace grant, environment, runtime input, or lifecycle callback.
type SkillProjection interface {
	ID() string
	Version() int
	Expected([]skills.SkillBundle) ([]skills.SkillReference, error)
	Destination(string, skills.SkillReference) (skills.SkillReference, string, error)
	Materialize(string, []skills.SkillBundle) error
}

type SkillsContribution struct {
	selected   []skills.SkillBundle
	expected   []skills.SkillReference
	projection SkillProjection
}

type SkillsBinding = category.Binding[[]skills.SkillReference, []skills.SkillBundle, SkillsContribution]

func NewSkillsBinding(discover func(context.Context) ([]skills.SkillBundle, error), projection SkillProjection) (SkillsBinding, error) {
	if discover == nil || projection == nil || projection.ID() == "" || projection.Version() < 1 {
		return SkillsBinding{}, errors.New("common Skills registration is incomplete")
	}
	return category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, SkillsContribution]{
		ID: SkillsCapabilityID, SchemaVersion: SkillsCapabilityVersion,
		Empty:  func() []skills.SkillReference { return []skills.SkillReference{} },
		Encode: EncodeSkillSelection, Decode: DecodeSkillSelection,
		Resolve: func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
			catalog, err := discover(ctx)
			if err != nil {
				return nil, fmt.Errorf("discover common Skill Catalog: %w", err)
			}
			return skills.ResolveReferences(references, catalog)
		},
		ResolveSyntax: func(references []skills.SkillReference) ([]skills.SkillBundle, error) {
			selected := make([]skills.SkillBundle, 0, len(references))
			for _, reference := range references {
				selected = append(selected, skills.SkillBundle{Reference: reference, DisplayName: filepath.Base(reference.RelativePath)})
			}
			return selected, nil
		},
		Contribute: func(selected []skills.SkillBundle) (SkillsContribution, error) {
			if err := ValidateCommonDestinations(selected); err != nil {
				return SkillsContribution{}, err
			}
			expected, err := projection.Expected(selected)
			if err != nil {
				return SkillsContribution{}, err
			}
			return SkillsContribution{selected: selected, expected: expected, projection: projection}, nil
		},
		Count: func(references []skills.SkillReference) int { return len(references) },
	})
}

func EncodeSkillSelection(references []skills.SkillReference) (json.RawMessage, error) {
	ordered := append([]skills.SkillReference(nil), references...)
	if ordered == nil {
		ordered = []skills.SkillReference{}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Source != ordered[j].Source {
			return ordered[i].Source < ordered[j].Source
		}
		return ordered[i].RelativePath < ordered[j].RelativePath
	})
	return json.Marshal(ordered)
}

func DecodeSkillSelection(selection json.RawMessage) ([]skills.SkillReference, error) {
	var references []skills.SkillReference
	decoder := json.NewDecoder(bytes.NewReader(selection))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&references); err != nil {
		return nil, err
	}
	if references == nil {
		return nil, errors.New("expected an array, got null")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("unexpected data after selection")
		}
		return nil, err
	}
	for _, reference := range references {
		if reference.Source == "" || reference.RelativePath == "" {
			return nil, errors.New("invalid Skill Reference: source and relativePath are required")
		}
	}
	return references, nil
}

func (contribution SkillsContribution) Plan(ctx context.Context, _ string, plan *launch.Plan) error {
	return contribution.PlanResolved(ctx, "", profile.LegacyCurrentVersion, contribution.projection.ID(), plan)
}
func (contribution SkillsContribution) PlanResolved(ctx context.Context, _ string, sourceVersion int, overlay string, plan *launch.Plan) error {
	title := "Selected common Skill Bundles:"
	if sourceVersion < profile.CurrentVersion {
		title = "Selected global Skill Bundles managed by ACS:"
	}
	section := launch.PlanSection{Title: title, Items: make([]launch.PlanItem, 0, len(contribution.selected))}
	for _, bundle := range contribution.selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		label := bundle.DisplayName
		details := []launch.PlanDetail{{Label: "identity", Value: string(bundle.Reference.Source) + ":" + bundle.Reference.RelativePath}}
		if sourceVersion < profile.CurrentVersion {
			label = fmt.Sprintf("%s [%s]", bundle.DisplayName, bundle.Reference.Source)
			details = []launch.PlanDetail{{Label: "source", Value: bundle.BundlePath}}
		}
		if sourceVersion >= profile.CurrentVersion {
			details = append(details, launch.PlanDetail{Label: "common", Value: commonDestination(filepath.Join("<session>", "home"), bundle.Reference)})
		}
		if overlay == contribution.projection.ID() {
			_, destination, err := contribution.projection.Destination(filepath.Join("<session>", "home"), bundle.Reference)
			if err != nil {
				return err
			}
			projectionLabel := "target projection"
			if sourceVersion < profile.CurrentVersion {
				projectionLabel = "Session"
			}
			details = append(details, launch.PlanDetail{Label: projectionLabel, Value: destination})
		}
		section.Items = append(section.Items, launch.PlanItem{Label: label, Details: details})
	}
	plan.Sections = append(plan.Sections, section)
	return nil
}
func (contribution SkillsContribution) Materialize(sessionHome string) error {
	return contribution.projection.Materialize(sessionHome, contribution.selected)
}
func (contribution SkillsContribution) MaterializeResolved(sessionHome string, sourceVersion int, overlay string) error {
	if sourceVersion < profile.CurrentVersion {
		return contribution.projection.Materialize(sessionHome, contribution.selected)
	}
	materialized := make([]skills.SkillBundle, 0, len(contribution.selected))
	for _, bundle := range contribution.selected {
		destination := commonDestination(sessionHome, bundle.Reference)
		if err := skillmaterial.CopyBundle(bundle.BundlePath, destination); err != nil {
			return fmt.Errorf("prepare common Skill Bundle %q: %w", identity(bundle.Reference), err)
		}
		materialized = append(materialized, skills.SkillBundle{Reference: bundle.Reference, DisplayName: bundle.DisplayName, BundlePath: destination})
	}
	if overlay == contribution.projection.ID() {
		return contribution.projection.Materialize(sessionHome, materialized)
	}
	return nil
}
func (SkillsContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (contribution SkillsContribution) DevinExpectedCatalog() []skills.SkillReference {
	return append([]skills.SkillReference(nil), contribution.expected...)
}
func commonDestination(home string, reference skills.SkillReference) string {
	return filepath.Join(home, ".acs", "common", "v1", SkillsCapabilityID, string(reference.Source), filepath.Clean(reference.RelativePath))
}
func identity(reference skills.SkillReference) string {
	return string(reference.Source) + ":" + reference.RelativePath
}

func ValidateCommonDestinations(selected []skills.SkillBundle) error {
	seen := make(map[string]skills.SkillReference, len(selected))
	keys := make([]string, 0, len(selected))
	for _, bundle := range selected {
		clean := filepath.Clean(bundle.Reference.RelativePath)
		if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid common Skill destination %q", identity(bundle.Reference))
		}
		key := strings.ToLower(norm.NFC.String(string(bundle.Reference.Source) + "/" + filepath.ToSlash(clean)))
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("common Skill destination collision between %q and %q", identity(previous), identity(bundle.Reference))
		}
		seen[key], keys = bundle.Reference, append(keys, key)
	}
	sort.Strings(keys)
	for index := 1; index < len(keys); index++ {
		if strings.HasPrefix(keys[index], keys[index-1]+"/") {
			return fmt.Errorf("common Skill destinations overlap: %q and %q", keys[index-1], keys[index])
		}
	}
	return nil
}

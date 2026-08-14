package devin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const (
	skillsCategoryID            = "skills"
	skillsCategorySchemaVersion = 1
)

// NewSkillsProfile is a compatibility helper for callers constructing Devin
// Profiles outside the interactive editor.
func NewSkillsProfile(name string, references []skills.SkillReference) profile.Profile {
	selection, err := encodeSkillSelection(references)
	if err != nil {
		panic(fmt.Sprintf("encode Skills selection: %v", err))
	}
	return profile.Profile{Version: profile.CurrentVersion, Name: name, Target: "devin", Categories: map[string]profile.CategoryPayload{
		skillsCategoryID: {SchemaVersion: skillsCategorySchemaVersion, Selection: selection},
	}}
}

// SkillReferences decodes the Skills selection from a Devin Profile.
func SkillReferences(candidate profile.Profile) ([]skills.SkillReference, error) {
	payload, exists := candidate.Categories[skillsCategoryID]
	if !exists {
		return []skills.SkillReference{}, nil
	}
	if payload.SchemaVersion != skillsCategorySchemaVersion {
		return nil, fmt.Errorf("Skills category uses unsupported schema version %d", payload.SchemaVersion)
	}
	references, err := decodeSkillSelection(payload.Selection)
	if err != nil {
		return nil, fmt.Errorf("decode Skills category selection: %w", err)
	}
	return references, nil
}

type skillsContribution struct {
	adapter  *Adapter
	selected []skills.SkillBundle
	expected []skills.SkillReference
}

func newCategoryRegistry(adapter *Adapter) (*category.Registry, category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillsContribution], error) {
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, skillsContribution]{
		ID:            skillsCategoryID,
		SchemaVersion: skillsCategorySchemaVersion,
		Empty:         func() []skills.SkillReference { return []skills.SkillReference{} },
		Encode:        encodeSkillSelection,
		Decode:        decodeSkillSelection,
		Resolve: func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
			catalog, err := adapter.DiscoverGlobalSkillCatalog(ctx)
			if err != nil {
				return nil, fmt.Errorf("discover Devin global Skill Catalog: %w", err)
			}
			return skills.ResolveReferences(references, catalog)
		},
		Contribute: func(selected []skills.SkillBundle) (skillsContribution, error) {
			expected := make([]skills.SkillReference, 0, len(selected))
			for _, bundle := range selected {
				reference, _, err := bundlePlacement(filepath.Join("<session>", "home"), bundle.Reference)
				if err != nil {
					return skillsContribution{}, err
				}
				expected = append(expected, reference)
			}
			sortSkillReferences(expected)
			return skillsContribution{adapter: adapter, selected: selected, expected: expected}, nil
		},
		Count: func(references []skills.SkillReference) int { return len(references) },
	})
	if err != nil {
		return nil, category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillsContribution]{}, err
	}
	registry, err := category.NewRegistryWithLegacy(
		"devin",
		[]category.Registration{binding.Registration()},
		category.LegacyDecoder{Version: 1, Decode: decodeVersionOneProfile},
	)
	if err != nil {
		return nil, category.Binding[[]skills.SkillReference, []skills.SkillBundle, skillsContribution]{}, err
	}
	return registry, binding, nil
}

func encodeSkillSelection(references []skills.SkillReference) (json.RawMessage, error) {
	ordered := append([]skills.SkillReference(nil), references...)
	if ordered == nil {
		ordered = []skills.SkillReference{}
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].Source != ordered[right].Source {
			return ordered[left].Source < ordered[right].Source
		}
		return ordered[left].RelativePath < ordered[right].RelativePath
	})
	return json.Marshal(ordered)
}

func decodeSkillSelection(selection json.RawMessage) ([]skills.SkillReference, error) {
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

func decodeVersionOneProfile(contents []byte) (profile.Profile, error) {
	var legacy struct {
		Version         int             `json:"version"`
		Name            string          `json:"name"`
		Target          string          `json:"target"`
		SkillReferences json.RawMessage `json:"skillReferences"`
	}
	if err := json.Unmarshal(contents, &legacy); err != nil {
		return profile.Profile{}, err
	}
	references, err := decodeSkillSelection(legacy.SkillReferences)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("decode version-1 skillReferences: %w", err)
	}
	selection, err := encodeSkillSelection(references)
	if err != nil {
		return profile.Profile{}, err
	}
	return profile.Profile{
		Version: profile.CurrentVersion,
		Name:    legacy.Name,
		Target:  legacy.Target,
		Categories: map[string]profile.CategoryPayload{
			skillsCategoryID: {SchemaVersion: skillsCategorySchemaVersion, Selection: selection},
		},
	}, nil
}

func (contribution skillsContribution) Plan(ctx context.Context, workingDirectory string, plan *launch.Plan) error {
	return contribution.adapter.planSkills(ctx, workingDirectory, contribution.selected, plan)
}

func (contribution skillsContribution) Materialize(sessionHome string) error {
	for _, rule := range globalSourceRules {
		if err := os.MkdirAll(filepath.Join(sessionHome, rule.RelativeDirectory), 0o700); err != nil {
			return fmt.Errorf("prepare Devin Session global source %q: %w", rule.Source, err)
		}
	}
	seen := make(map[skills.SkillReference]struct{}, len(contribution.selected))
	for _, bundle := range contribution.selected {
		reference, destination, err := bundlePlacement(sessionHome, bundle.Reference)
		if err != nil {
			return err
		}
		if _, exists := seen[reference]; exists {
			return fmt.Errorf("duplicate Skill Reference %q", diagnosticIdentity(reference))
		}
		seen[reference] = struct{}{}
		if err := copyBundle(bundle.BundlePath, destination); err != nil {
			return fmt.Errorf("prepare Devin Session Skill Bundle %q: %w", diagnosticIdentity(reference), err)
		}
	}
	return nil
}

func (contribution skillsContribution) Verify(ctx context.Context, verification launch.VerificationContext) error {
	return contribution.adapter.verifySkillIsolation(ctx, &Session{
		RootDir:          verification.SessionDirectory,
		HomeDir:          verification.SessionHome,
		TemporaryDir:     verification.TemporaryDirectory,
		SessionsDir:      verification.SessionsDirectory,
		WorkingDirectory: verification.WorkingDirectory,
		expectedCatalog:  contribution.expected,
	})
}

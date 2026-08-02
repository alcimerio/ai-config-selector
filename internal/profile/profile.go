// Package profile owns Profile persistence and validation.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const (
	CurrentVersion      = 2
	SkillsCategoryID    = "skills"
	SkillsSchemaVersion = 1
)

var (
	ErrInvalidProfileName = errors.New("invalid Profile name")
	profileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Profile struct {
	Version    int                        `json:"version"`
	Name       string                     `json:"name"`
	Target     string                     `json:"target"`
	Categories map[string]CategoryPayload `json:"categories"`
}

type CategoryPayload struct {
	SchemaVersion int             `json:"schemaVersion"`
	Selection     json.RawMessage `json:"selection"`
}

func NewSkillsProfile(name, target string, references []skills.SkillReference) Profile {
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
	selection, err := json.Marshal(ordered)
	if err != nil {
		panic(fmt.Sprintf("encode Skills selection: %v", err))
	}
	return Profile{
		Version: CurrentVersion,
		Name:    name,
		Target:  target,
		Categories: map[string]CategoryPayload{
			SkillsCategoryID: {
				SchemaVersion: SkillsSchemaVersion,
				Selection:     selection,
			},
		},
	}
}

func SkillReferences(profile Profile) ([]skills.SkillReference, error) {
	payload, exists := profile.Categories[SkillsCategoryID]
	if !exists {
		return []skills.SkillReference{}, nil
	}
	if payload.SchemaVersion != SkillsSchemaVersion {
		return nil, fmt.Errorf("Skills category uses unsupported schema version %d", payload.SchemaVersion)
	}
	references, err := decodeSkillReferences(payload.Selection)
	if err != nil {
		return nil, fmt.Errorf("decode Skills category selection: %w", err)
	}
	return references, nil
}

func decodeSkillReferences(selection []byte) ([]skills.SkillReference, error) {
	var references []skills.SkillReference
	decoder := json.NewDecoder(bytes.NewReader(selection))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&references); err != nil {
		return nil, err
	}
	if references == nil {
		return nil, errors.New("expected an array, got null")
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return nil, err
	}
	for _, reference := range references {
		if reference.Source == "" || reference.RelativePath == "" {
			return nil, fmt.Errorf("invalid Skill Reference: source and relativePath are required")
		}
	}
	return references, nil
}

func normalizeCurrentProfile(candidate Profile) (Profile, error) {
	if candidate.Version != CurrentVersion {
		return Profile{}, fmt.Errorf("unsupported schema version %d", candidate.Version)
	}
	categoryIDs := make([]string, 0, len(candidate.Categories))
	for categoryID := range candidate.Categories {
		categoryIDs = append(categoryIDs, categoryID)
	}
	sort.Strings(categoryIDs)
	for _, categoryID := range categoryIDs {
		if categoryID != SkillsCategoryID {
			return Profile{}, fmt.Errorf("unknown Profile category %q", categoryID)
		}
	}
	if candidate.Categories == nil {
		candidate.Categories = make(map[string]CategoryPayload)
	}
	if _, exists := candidate.Categories[SkillsCategoryID]; !exists {
		empty := NewSkillsProfile(candidate.Name, candidate.Target, nil)
		candidate.Categories[SkillsCategoryID] = empty.Categories[SkillsCategoryID]
	}
	if _, err := SkillReferences(candidate); err != nil {
		return Profile{}, err
	}
	return candidate, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected data after selection")
	}
	return err
}

func ValidateName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("%w %q: use 1-64 ASCII letters, numbers, dots, underscores, or hyphens, starting with a letter or number", ErrInvalidProfileName, name)
	}
	return nil
}

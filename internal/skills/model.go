// Package skills contains the CLI-neutral Skill Catalog domain types.
package skills

import "fmt"

// Source identifies one CLI Adapter-owned global Skill Bundle source.
type Source string

// SkillReference is the stable source-plus-relative-path identity persisted in
// a Profile. It is resolved against a later Skill Catalog without rebinding.
type SkillReference struct {
	Source       Source `json:"source"`
	RelativePath string `json:"relativePath"`
}

// SkillBundle is one selectable entry in the current global Skill Catalog.
type SkillBundle struct {
	Reference   SkillReference
	DisplayName string
	BundlePath  string
}

// ResolveReferences resolves each strict Skill Reference against the current
// Skill Catalog without rebinding missing or ambiguous references.
func ResolveReferences(references []SkillReference, catalog []SkillBundle) ([]SkillBundle, error) {
	selected := make([]SkillBundle, 0, len(references))
	for _, reference := range references {
		matches := make([]SkillBundle, 0, 1)
		for _, bundle := range catalog {
			if bundle.Reference == reference {
				matches = append(matches, bundle)
			}
		}
		identity := string(reference.Source) + ":" + reference.RelativePath
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("Skill Reference %q is missing from the current Skill Catalog", identity)
		case 1:
			selected = append(selected, matches[0])
		default:
			return nil, fmt.Errorf("Skill Reference %q is ambiguous in the current Skill Catalog", identity)
		}
	}
	return selected, nil
}

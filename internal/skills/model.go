// Package skills contains the CLI-neutral Skill Catalog domain types.
package skills

import (
	"fmt"
	"sort"
	"strconv"
)

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
	observed := catalogDiagnosticIdentities(catalog)
	for _, reference := range references {
		matches := make([]SkillBundle, 0, 1)
		for _, bundle := range catalog {
			if bundle.Reference == reference {
				matches = append(matches, bundle)
			}
		}
		identity := diagnosticIdentity(reference)
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("Skill Reference %s is missing from the current Skill Catalog (observed Skill References %v)", identity, observed)
		case 1:
			selected = append(selected, matches[0])
		default:
			return nil, fmt.Errorf("Skill Reference %s is ambiguous in the current Skill Catalog (observed Skill References %v)", identity, observed)
		}
	}
	return selected, nil
}

func catalogDiagnosticIdentities(catalog []SkillBundle) []string {
	identities := make([]string, 0, len(catalog))
	for _, bundle := range catalog {
		identities = append(identities, diagnosticIdentity(bundle.Reference))
	}
	sort.Strings(identities)
	return identities
}

func diagnosticIdentity(reference SkillReference) string {
	return strconv.QuoteToASCII(string(reference.Source) + ":" + reference.RelativePath)
}

// Discovery records partial source availability for selection repair. A failed
// source is not evidence that a saved reference is missing.
type Discovery struct {
	Bundles            []SkillBundle
	UnavailableSources map[Source]bool
}

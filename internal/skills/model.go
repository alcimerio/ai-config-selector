// Package skills contains the CLI-neutral Skill Catalog domain types.
package skills

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
	SourceRoot  string
	Path        string
}

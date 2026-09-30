package profileinspect

import (
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Checks struct {
	Sources string `json:"sources"`
	Auth    string `json:"auth"`
	Runtime string `json:"runtime"`
}
type Result struct {
	FormatVersion int         `json:"formatVersion"`
	Operation     string      `json:"operation"`
	Storage       string      `json:"storage"`
	Entries       []Entry     `json:"entries"`
	Diagnostic    *Diagnostic `json:"diagnostic"`
	Checks        Checks      `json:"checks"`
}
type Entry struct {
	File          *string     `json:"file"`
	Name          *string     `json:"name"`
	Status        string      `json:"status"`
	StoredVersion *int        `json:"storedVersion"`
	Target        *string     `json:"target"`
	Categories    []Category  `json:"categories"`
	Overlays      []Overlay   `json:"overlays"`
	Workspace     *string     `json:"workspaceAccess"`
	Diagnostic    *Diagnostic `json:"diagnostic"`
}
type Overlay struct {
	ID      string `json:"id"`
	Version *int   `json:"version"`
	Support string `json:"support"`
}
type Category struct {
	ID            string                   `json:"id"`
	SchemaVersion *int                     `json:"schemaVersion"`
	Selection     []skills.SkillReference  `json:"selection,omitempty"`
	Instructions  []instructions.Reference `json:"instructions,omitempty"`

	// Retain only aggregate metadata for capabilities with private selections.
	selectedCount *int
}

func newResult(operation string) Result {
	return Result{FormatVersion: 1, Operation: operation, Storage: "unavailable", Entries: []Entry{}, Checks: Checks{"unchecked", "unchecked", "unchecked"}}
}
func newEntry(name string) Entry {
	entry := Entry{Categories: []Category{}, Overlays: []Overlay{}}
	if profile.ValidateName(name) == nil {
		entry.Name = &name
	}
	return entry
}
func diagnostic(code string) *Diagnostic {
	return &Diagnostic{Code: code, Message: map[string]string{
		"storage_unavailable": "Profile storage cannot be safely opened or enumerated.",
		"invalid_name":        "Profile names require 1-64 ASCII letters, numbers, dots, underscores or hyphens, starting with a letter or number.",
		"missing":             "Stored Profile is missing.", "unreadable": "Stored Profile cannot be read.",
		"non_regular": "Stored Profile is not a regular file.", "too_large": "Stored Profile exceeds the 1 MiB inspection limit.",
		"invalid_structure": "Stored Profile structure is invalid.", "identity_mismatch": "Stored Profile name does not match its filename.",
		"unsupported_content": "Stored Profile contains unknown or unsupported content.",
	}[code]}
}
func (entry Entry) failed(code string) Entry {
	entry.Status = "invalid"
	switch code {
	case "missing", "unreadable":
		entry.Status = code
	case "unsupported_content":
		entry.Status = "unsupported"
	}
	entry.Diagnostic = diagnostic(code)
	entry.Target = nil
	entry.Categories = []Category{}
	entry.Overlays = []Overlay{}
	entry.Workspace = nil
	return entry
}

// Unavailable returns a sanitized failure before storage can be opened.
func Unavailable(operation string) Result {
	result := newResult(operation)
	result.Diagnostic = diagnostic("storage_unavailable")
	return result
}
func (result Result) ExitCode() int {
	if result.Diagnostic != nil {
		return 1
	}
	if result.Operation == "show" && (len(result.Entries) != 1 || result.Entries[0].Status != "valid") {
		return 1
	}
	return 0
}

// SelectionCount reports the number of stored selections when the capability
// is a collection. Scalar capabilities, such as workspace access, have no count.
// Private path, executable, environment and MCP details are never retained.
func (category Category) SelectionCount() (int, bool) {
	switch category.ID {
	case "skills":
		return len(category.Selection), true
	case "instructions":
		return len(category.Instructions), true
	default:
		if category.selectedCount != nil {
			return *category.selectedCount, true
		}
		return 0, false
	}
}

func countedCategory(id string, version, count int) Category {
	return Category{ID: id, SchemaVersion: &version, selectedCount: &count}
}

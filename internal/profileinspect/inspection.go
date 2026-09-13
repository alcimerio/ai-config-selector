// Package profileinspect reads persisted Profile structure without launch,
// migration, discovery, authentication, or Session dependencies.
package profileinspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const maxProfileBytes = 1 << 20

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
	ID            string                  `json:"id"`
	SchemaVersion *int                    `json:"schemaVersion"`
	Selection     []skills.SkillReference `json:"selection"`
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

// InspectBytes strictly inspects one bounded exact stored representation, bound
// to its requested filename identity. It performs no filesystem or codec work.
func InspectBytes(name string, data []byte) Entry {
	entry := Entry{Name: &name, Categories: []Category{}, Overlays: []Overlay{}}
	if profile.ValidateName(name) != nil || len(data) > maxProfileBytes {
		return entry.failed("invalid_structure")
	}
	return decode(entry, data)
}

func decode(entry Entry, data []byte) Entry {
	// Reject ambiguous duplicate keys and invalid UTF-8 before map decoding.
	if !utf8.Valid(data) || !pairedUnicodeEscapes(data) || uniqueJSON(data) != nil {
		return entry.failed("invalid_structure")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || envelope == nil {
		return entry.failed("invalid_structure")
	}
	var version int
	if !required(envelope, "version", &version) {
		return entry.failed("invalid_structure")
	}
	entry.StoredVersion = &version
	if version != 1 && version != 2 && version != 3 {
		return entry.failed("unsupported_content")
	}
	if version == 3 {
		return decodeVersionThree(entry, envelope)
	}
	keys := []string{"version", "name", "target", "categories"}
	if version == 1 {
		keys[3] = "skillReferences"
	}
	if unknown(envelope, keys...) {
		return entry.failed("unsupported_content")
	}
	var name, target string
	if !required(envelope, "name", &name) || profile.ValidateName(name) != nil || !required(envelope, "target", &target) {
		return entry.failed("invalid_structure")
	}
	if entry.Name == nil || name != *entry.Name {
		return entry.failed("identity_mismatch")
	}
	if target != "devin" {
		return entry.failed("unsupported_content")
	}
	categories := []Category{}
	if version == 1 {
		references, code := decodeReferences(envelope["skillReferences"])
		if code != "" {
			return entry.failed(code)
		}
		categories = append(categories, Category{ID: "skills", Selection: references})
	} else {
		var payloads map[string]json.RawMessage
		if !required(envelope, "categories", &payloads) {
			return entry.failed("invalid_structure")
		}
		for id := range payloads {
			if id != "skills" {
				return entry.failed("unsupported_content")
			}
		}
		if raw, ok := payloads["skills"]; ok {
			var payload map[string]json.RawMessage
			if json.Unmarshal(raw, &payload) != nil || payload == nil {
				return entry.failed("invalid_structure")
			}
			if unknown(payload, "schemaVersion", "selection") {
				return entry.failed("unsupported_content")
			}
			var schema int
			if !required(payload, "schemaVersion", &schema) {
				return entry.failed("invalid_structure")
			}
			if schema != 1 {
				return entry.failed("unsupported_content")
			}
			references, code := decodeReferences(payload["selection"])
			if code != "" {
				return entry.failed(code)
			}
			categories = append(categories, Category{ID: "skills", SchemaVersion: &schema, Selection: references})
		}
	}
	entry.Status = "valid"
	entry.Target = &target
	entry.Categories = categories
	return entry
}

func decodeVersionThree(entry Entry, envelope map[string]json.RawMessage) Entry {
	if unknown(envelope, "version", "name", "common", "overlays") {
		return entry.failed("unsupported_content")
	}
	var name string
	if !required(envelope, "name", &name) || profile.ValidateName(name) != nil {
		return entry.failed("invalid_structure")
	}
	if entry.Name == nil || name != *entry.Name {
		return entry.failed("identity_mismatch")
	}
	var common map[string]json.RawMessage
	if !required(envelope, "common", &common) || common == nil {
		return entry.failed("unsupported_content")
	}
	for id := range common {
		if _, supported := commonCapability(id); !supported {
			return entry.failed("unsupported_content")
		}
	}
	capabilities := CommonCapabilities()
	if len(common) < 2 || len(common) > len(capabilities) {
		return entry.failed("invalid_structure")
	}
	skillsPayload, ok := common["skills"]
	if !ok {
		return entry.failed("invalid_structure")
	}
	version, selection, code := decodeCommonPayload(skillsPayload)
	if code != "" || version != 1 {
		if code == "" {
			code = "unsupported_content"
		}
		return entry.failed(code)
	}
	references, code := decodeReferences(selection)
	if code != "" {
		return entry.failed(code)
	}
	entry.Categories = append(entry.Categories, Category{ID: "skills", SchemaVersion: &version, Selection: references})
	workspacePayload, ok := common["workspace"]
	if !ok {
		return entry.failed("invalid_structure")
	}
	workspaceVersion, workspaceSelection, code := decodeCommonPayload(workspacePayload)
	if code != "" || workspaceVersion != 1 {
		if code == "" {
			code = "unsupported_content"
		}
		return entry.failed(code)
	}
	var workspace map[string]json.RawMessage
	if json.Unmarshal(workspaceSelection, &workspace) != nil || workspace == nil || unknown(workspace, "access") {
		return entry.failed("unsupported_content")
	}
	var access string
	if !required(workspace, "access", &access) || (access != "read-only" && access != "read-write") {
		return entry.failed("invalid_structure")
	}
	entry.Workspace = &access
	entry.Categories = append(entry.Categories, Category{ID: "workspace", SchemaVersion: &workspaceVersion, Selection: []skills.SkillReference{}})
	if pathsPayload, exists := common["paths"]; exists {
		pathsVersion, pathsSelection, code := decodeCommonPayload(pathsPayload)
		if code != "" || pathsVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		if _, err := pathintent.Decode(pathsSelection); err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, Category{ID: "paths", SchemaVersion: &pathsVersion})
	}
	if executablesPayload, exists := common["executables"]; exists {
		executablesVersion, executableSelection, code := decodeCommonPayload(executablesPayload)
		if code != "" || executablesVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		if _, err := executableintent.Decode(executableSelection); err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, Category{ID: "executables", SchemaVersion: &executablesVersion})
	}
	if environmentPayload, exists := common["environment"]; exists {
		environmentVersion, environmentSelection, code := decodeCommonPayload(environmentPayload)
		if code != "" || environmentVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		if _, err := environmentintent.Decode(environmentSelection); err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, Category{ID: "environment", SchemaVersion: &environmentVersion})
	}
	var overlays map[string]json.RawMessage
	if !required(envelope, "overlays", &overlays) || overlays == nil {
		return entry.failed("invalid_structure")
	}
	ids := make([]string, 0, len(overlays))
	for id := range overlays {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var payload map[string]json.RawMessage
		if json.Unmarshal(overlays[id], &payload) != nil || payload == nil {
			return entry.failed("invalid_structure")
		}
		var overlayVersion int
		if !required(payload, "version", &overlayVersion) || overlayVersion < 1 {
			return entry.failed("invalid_structure")
		}
		support := "inactive-unknown"
		if id == "devin" {
			support = "unsupported"
			if overlayVersion == 1 && !unknown(payload, "version") {
				support = "supported"
			}
		} else if id == "codex" {
			if overlayVersion == 1 {
				support = "unsupported"
				if !unknown(payload, "version", "authRef") {
					support = "supported"
					if encoded, exists := payload["authRef"]; exists {
						var authRef string
						if json.Unmarshal(encoded, &authRef) != nil || authRef == "" {
							support = "unsupported"
						} else if _, err := codexauthresource.ParseCredentialRef(authRef); err != nil {
							support = "unsupported"
						}
					}
				}
			}
		}
		entry.Overlays = append(entry.Overlays, Overlay{ID: id, Version: &overlayVersion, Support: support})
	}
	target := "common"
	entry.Target, entry.Status = &target, "valid"
	return entry
}

func decodeCommonPayload(raw json.RawMessage) (int, json.RawMessage, string) {
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil || payload == nil {
		return 0, nil, "invalid_structure"
	}
	if unknown(payload, "version", "selection") {
		return 0, nil, "unsupported_content"
	}
	var version int
	if !required(payload, "version", &version) || version < 1 {
		return 0, nil, "invalid_structure"
	}
	selection, ok := payload["selection"]
	if !ok || bytes.Equal(bytes.TrimSpace(selection), []byte("null")) {
		return 0, nil, "invalid_structure"
	}
	return version, selection, ""
}
func required(fields map[string]json.RawMessage, key string, destination any) bool {
	raw, ok := fields[key]
	return ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, destination) == nil
}
func unknown(fields map[string]json.RawMessage, keys ...string) bool {
	for field := range fields {
		known := false
		for _, key := range keys {
			if field == key {
				known = true
				break
			}
		}
		if !known {
			return true
		}
	}
	return false
}
func decodeReferences(raw json.RawMessage) ([]skills.SkillReference, string) {
	var values []map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, "invalid_structure"
	}
	references := make([]skills.SkillReference, 0, len(values))
	seen := map[skills.SkillReference]bool{}
	for _, fields := range values {
		if unknown(fields, "source", "relativePath") {
			return nil, "unsupported_content"
		}
		var reference skills.SkillReference
		if !required(fields, "source", &reference.Source) || !required(fields, "relativePath", &reference.RelativePath) || reference.Source == "" {
			return nil, "invalid_structure"
		}
		relative := reference.RelativePath
		clean := path.Clean(relative)
		if relative == "" || strings.ContainsRune(relative, 0) || path.IsAbs(relative) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, "invalid_structure"
		}
		if reference.Source != "devin-config" && reference.Source != "shared-agents" {
			return nil, "unsupported_content"
		}
		identity := reference
		identity.RelativePath = clean
		if seen[identity] {
			return nil, "invalid_structure"
		}
		seen[identity] = true
		references = append(references, reference)
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].Source != references[j].Source {
			return references[i].Source < references[j].Source
		}
		return references[i].RelativePath < references[j].RelativePath
	})
	return references, ""
}

// Limit nesting as well as bytes; unknown payloads never enter output structs.
func uniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := uniqueValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate key")
			}
			seen[name] = true
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = decoder.Token()
	return err
}

// Go's JSON decoder replaces lone UTF-16 surrogates with U+FFFD. Validate
// escapes before decoding so inspection cannot silently change stored identity.
// Skip every non-Unicode escape as a pair, including escaped backslashes;
// the JSON decoder remains responsible for general syntax validation.
func pairedUnicodeEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xDC00 && code <= 0xDFFF {
			return false
		}
		if code >= 0xD800 && code <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

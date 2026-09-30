// Package profileinspect reads persisted Profile structure without launch,
// migration, discovery, authentication, or Session dependencies.
package profileinspect

import (
	"bytes"
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"github.com/alcimerio/ai-config-selector/internal/strictjson"
)

const maxProfileBytes = 1 << 20

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
	if !strictjson.ValidUnicode(data) || uniqueJSON(data) != nil {
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

// Limits remain owned by Profile inspection, independent of other JSON users.
func uniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return strictjson.Scan(decoder, strictjson.Limits{MaxDepth: 64}, nil)
}

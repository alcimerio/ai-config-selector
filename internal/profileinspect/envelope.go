package profileinspect

import (
	"encoding/json"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/capabilitycatalog"
	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/exclusionintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/mcpintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func decodeEnvelope(entry Entry, envelope map[string]json.RawMessage) Entry {
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
		if _, supported := capabilitycatalog.LookupCommon(id); !supported {
			return entry.failed("unsupported_content")
		}
	}
	capabilities := capabilitycatalog.CommonCapabilities()
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
	selectedPaths := pathintent.Empty()
	selectedExecutables := executableintent.Empty()
	selectedEnvironment := environmentintent.Empty()
	selectedMCP := mcpintent.Empty()
	var err error
	if pathsPayload, exists := common["paths"]; exists {
		pathsVersion, pathsSelection, code := decodeCommonPayload(pathsPayload)
		if code != "" || pathsVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		selectedPaths, err = pathintent.Decode(pathsSelection)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, countedCategory("paths", pathsVersion, len(selectedPaths.Entries)))
	}
	if payload, exists := common["exclusions"]; exists {
		version, selection, code := decodeCommonPayload(payload)
		if code != "" || version != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		exclusions, err := exclusionintent.Decode(selection)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, countedCategory("exclusions", version, len(exclusions.Entries)))
	}
	if executablesPayload, exists := common["executables"]; exists {
		executablesVersion, executableSelection, code := decodeCommonPayload(executablesPayload)
		if code != "" || executablesVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		selectedExecutables, err = executableintent.Decode(executableSelection)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, countedCategory("executables", executablesVersion, len(selectedExecutables.Entries)))
	}
	if environmentPayload, exists := common["environment"]; exists {
		environmentVersion, environmentSelection, code := decodeCommonPayload(environmentPayload)
		if code != "" || environmentVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		selectedEnvironment, err = environmentintent.Decode(environmentSelection)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, countedCategory("environment", environmentVersion, len(selectedEnvironment.Entries)))
	}
	if mcpPayload, exists := common["mcp"]; exists {
		mcpVersion, mcpSelection, code := decodeCommonPayload(mcpPayload)
		if code != "" || mcpVersion != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		selectedMCP, err = mcpintent.Decode(mcpSelection)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, countedCategory("mcp", mcpVersion, len(selectedMCP.Servers)))
	}
	if err := mcpintent.ValidateReferences(selectedMCP, selectedExecutables, selectedPaths, selectedEnvironment); err != nil {
		return entry.failed("invalid_structure")
	}
	if instructionsPayload, exists := common["instructions"]; exists {
		iv, raw, code := decodeCommonPayload(instructionsPayload)
		if code != "" || iv != 1 {
			if code == "" {
				code = "unsupported_content"
			}
			return entry.failed(code)
		}
		refs, err := instructions.Decode(raw)
		if err != nil {
			return entry.failed("invalid_structure")
		}
		entry.Categories = append(entry.Categories, Category{ID: "instructions", SchemaVersion: &iv, Instructions: refs})
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

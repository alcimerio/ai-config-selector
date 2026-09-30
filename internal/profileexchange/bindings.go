package profileexchange

import (
	"encoding/json"
	"reflect"

	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// bindDocument resolves only an admitted portable document. No candidate is
// constructed until the complete local binding set has passed validation.
func bindDocument(admitted admittedDocument, bindingData []byte, name string, result Result) Result {
	doc := admitted.document
	if bindingData == nil {
		if result.RequiredSources+result.RequiredAuthentication+result.RequiredPaths+result.RequiredExecutables+result.RequiredEnvironment != 0 {
			result.Code = CodeBindingRequired
			result.Bindings = "unresolved"
			return result
		}
		if doc.ExchangeVersion == 1 {
			bindingData = []byte(`{"bindingVersion":1,"sources":{},"authentications":{}}`)
		} else if doc.ExchangeVersion == 2 {
			bindingData = []byte(`{"bindingVersion":2,"sources":{},"authentications":{},"paths":{},"executables":{}}`)
		} else {
			bindingData = []byte(`{"bindingVersion":3,"sources":{},"authentications":{},"paths":{},"executables":{},"environment":{}}`)
		}
	}
	if len(bindingData) > MaxBytes {
		result.Code = CodeLimitExceeded
		return result
	}
	if code := preflight(bindingData); code != CodeValid {
		result.Code = code
		return result
	}
	if err := validateExactJSONFieldNames(bindingData, reflect.TypeOf(bindingDocument{})); err != nil {
		result.Code = CodeBindingInvalid
		return result
	}
	if doc.ExchangeVersion == 1 && jsonObjectFieldPresent(bindingData, "executables") {
		result.Code = CodeUnsupportedContent
		return result
	}
	if jsonObjectFieldNull(bindingData, "executables") {
		result.Code = CodeBindingInvalid
		return result
	}
	if jsonObjectFieldNull(bindingData, "environment") {
		result.Code = CodeBindingInvalid
		return result
	}
	var bindings bindingDocument
	if err := decodeStrict(bindingData, &bindings); err != nil {
		result.Code = CodeBindingInvalid
		return result
	}
	if bindings.BindingVersion < 3 && jsonObjectFieldPresent(bindingData, "environment") {
		result.Code = CodeBindingInvalid
		return result
	}
	bindingVersionCompatible := bindings.BindingVersion == doc.ExchangeVersion ||
		(doc.ExchangeVersion == 2 && len(doc.Requirements.Paths) == 0 && len(doc.Requirements.Executables) == 0 && bindings.BindingVersion == 1) ||
		(doc.ExchangeVersion == 3 && len(doc.Requirements.Environment) == 0 && bindings.BindingVersion == 2) ||
		(doc.ExchangeVersion == 3 && len(doc.Requirements.Paths) == 0 && len(doc.Requirements.Executables) == 0 && len(doc.Requirements.Environment) == 0 && bindings.BindingVersion == 1)
	if !bindingVersionCompatible || bindings.Sources == nil || bindings.Authentications == nil || (doc.ExchangeVersion >= 2 && len(doc.Requirements.Paths) != 0 && bindings.Paths == nil) || (doc.ExchangeVersion >= 2 && len(doc.Requirements.Executables) != 0 && bindings.Executables == nil) || (doc.ExchangeVersion == 3 && len(doc.Requirements.Environment) != 0 && bindings.Environment == nil) {
		result.Code = CodeBindingInvalid
		return result
	}
	if len(bindings.Sources) > maxBindings || len(bindings.Authentications) > maxBindings || len(bindings.Paths) > maxBindings || len(bindings.Executables) > maxBindings || len(bindings.Environment) > maxBindings {
		result.Code = CodeLimitExceeded
		return result
	}
	if !exactBindingKeys(doc.Requirements.Sources, bindings.Sources) || !exactBindingKeys(doc.Requirements.Authentications, bindings.Authentications) || !exactBindingKeys(doc.Requirements.Paths, bindings.Paths) || !exactBindingKeys(doc.Requirements.Executables, bindings.Executables) || !exactBindingKeys(doc.Requirements.Environment, bindings.Environment) {
		result.Code = CodeBindingRequired
		result.Bindings = "unresolved"
		return result
	}
	localReferences := make([]skills.SkillReference, 0, len(doc.Profile.Common.Skills.Selection))
	for _, reference := range doc.Profile.Common.Skills.Selection {
		local := bindings.Sources[reference.SourceBinding]
		if local != "devin-config" && local != "shared-agents" {
			result.Code = CodeBindingInvalid
			return result
		}
		localReferences = append(localReferences, skills.SkillReference{Source: skills.Source(local), RelativePath: reference.RelativePath})
	}
	localInstructionRefs := []instructions.Reference{}
	if doc.Profile.Common.Instructions != nil {
		for _, reference := range doc.Profile.Common.Instructions.Selection {
			local := bindings.Sources[reference.SourceBinding]
			if local != instructions.SourceID {
				result.Code = CodeBindingInvalid
				return result
			}
			localInstructionRefs = append(localInstructionRefs, instructions.Reference{Source: local, RelativePath: reference.RelativePath})
		}
	}
	if err := validateLocalReferences(localReferences); err != nil {
		result.Code = CodeBindingConflict
		return result
	}
	selections, code := bindCommonSelections(doc, bindings)
	if code != CodeValid {
		result.Code = code
		return result
	}
	overlays := make(map[string]profile.OverlayPayload, len(doc.Profile.Overlays))
	for id, payload := range doc.Profile.Overlays {
		switch id {
		case "devin":
			if payload.Version != 1 || payload.AuthBinding != "" {
				result.Code = CodeUnsupportedContent
				return result
			}
			overlays[id] = profile.OverlayPayload{Version: 1}
		case "codex":
			if payload.Version != 1 {
				result.Code = CodeUnsupportedContent
				return result
			}
			local := ""
			if payload.AuthBinding != "" {
				local = bindings.Authentications[payload.AuthBinding]
				if _, err := codexauth.ParseCredentialRef(local); err != nil {
					result.Code = CodeBindingInvalid
					return result
				}
			}
			overlays[id] = profile.OverlayPayload{Version: 1, AuthRef: local}
		default:
			result.Code = CodeUnsupportedContent
			return result
		}
	}
	if len(overlays) == 0 {
		result.Code = CodeInvalidStructure
		return result
	}
	encodedSkills, err := commonprofile.EncodeSkillSelection(localReferences)
	if err != nil {
		result.Code = CodeInvalidStructure
		return result
	}
	encodedInstructions, err := instructions.Encode(localInstructionRefs)
	if err != nil {
		result.Code = CodeInvalidStructure
		return result
	}
	encodedWorkspace, _ := json.Marshal(workspaceSelection{Access: doc.Profile.Common.Workspace.Selection.Access})
	candidate := profile.Profile{Version: profile.CurrentVersion, SourceVersion: profile.CurrentVersion, Name: name, Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: encodedSkills}, "workspace": {Version: 1, Selection: encodedWorkspace},
	}, Overlays: overlays}
	if doc.ExchangeVersion >= 2 {
		candidate.Common[commonprofile.PathsCapabilityID] = profile.CommonPayload{Version: commonprofile.PathsCapabilityVersion, Selection: selections.paths}
		candidate.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: commonprofile.ExecutablesCapabilityVersion, Selection: selections.executables}
	}
	if doc.ExchangeVersion == 3 {
		candidate.Common[commonprofile.EnvironmentCapabilityID] = profile.CommonPayload{Version: commonprofile.EnvironmentCapabilityVersion, Selection: selections.environment}
	}
	if doc.Profile.Common.MCP != nil {
		candidate.Common[commonprofile.MCPCapabilityID] = profile.CommonPayload{Version: commonprofile.MCPCapabilityVersion, Selection: selections.mcp}
	}
	if doc.Profile.Common.Instructions != nil {
		candidate.Common[commonprofile.InstructionsCapabilityID] = profile.CommonPayload{Version: commonprofile.InstructionsCapabilityVersion, Selection: encodedInstructions}
	}
	result.Code, result.Bindings, result.Candidate = CodeValid, "complete", &candidate
	return result
}

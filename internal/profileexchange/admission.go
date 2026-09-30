package profileexchange

import (
	"reflect"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// admittedDocument can enter local binding resolution only after portable
// syntax and semantics have passed admission.
type admittedDocument struct{ document }

// admitDocument validates the entire portable document without local bindings.
// A missing binding can be reported only after this boundary succeeds.
func admitDocument(data []byte) (admittedDocument, Code) {
	if len(data) > MaxBytes {
		return admittedDocument{}, CodeLimitExceeded
	}
	if code := preflight(data); code != CodeValid {
		return admittedDocument{}, code
	}
	var doc document
	if err := validateExactJSONFieldNames(data, reflect.TypeOf(doc)); err != nil {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if err := decodeStrict(data, &doc); err != nil {
		return admittedDocument{}, CodeUnsupportedContent
	}
	pathsPresent := exchangeCommonFieldPresent(data, "paths")
	executablesPresent := exchangeCommonFieldPresent(data, "executables")
	environmentPresent := exchangeCommonFieldPresent(data, "environment")
	instructionsPresent := exchangeCommonFieldPresent(data, "instructions")
	mcpPresent := exchangeCommonFieldPresent(data, "mcp")
	executableRequirementsPresent := exchangeRequirementsFieldPresent(data, "executables")
	environmentRequirementsPresent := exchangeRequirementsFieldPresent(data, "environment")
	if executableRequirementsPresent && exchangeRequirementsFieldNull(data, "executables") {
		return admittedDocument{}, CodeInvalidStructure
	}
	if environmentRequirementsPresent && exchangeRequirementsFieldNull(data, "environment") {
		return admittedDocument{}, CodeInvalidStructure
	}
	if doc.ExchangeVersion != 1 && doc.ExchangeVersion != 2 && doc.ExchangeVersion != ExchangeVersion {
		return admittedDocument{}, CodeUnsupportedVersion
	}
	if doc.Profile.Common.Skills.Version != 1 || doc.Profile.Common.Workspace.Version != 1 || len(doc.Profile.Common.Skills.Selection) > maxArray {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.ExchangeVersion == 1 {
		if pathsPresent || executablesPresent || environmentPresent || executableRequirementsPresent || environmentRequirementsPresent || doc.Requirements.Paths != nil || doc.Requirements.Executables != nil || doc.Requirements.Environment != nil {
			return admittedDocument{}, CodeUnsupportedContent
		}
	} else if doc.Profile.Common.Paths.Version != commonprofile.PathsCapabilityVersion || doc.Profile.Common.Paths.Selection == nil || len(doc.Profile.Common.Paths.Selection) > maximumPortablePathEntries {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.ExchangeVersion >= 2 && executablesPresent && (doc.Profile.Common.Executables.Version != commonprofile.ExecutablesCapabilityVersion || doc.Profile.Common.Executables.Selection == nil || len(doc.Profile.Common.Executables.Selection) > 128) {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.ExchangeVersion == 2 && (environmentPresent || environmentRequirementsPresent || doc.Requirements.Environment != nil) {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.ExchangeVersion == ExchangeVersion && (!environmentPresent || doc.Profile.Common.Environment.Version != commonprofile.EnvironmentCapabilityVersion || doc.Profile.Common.Environment.Selection == nil || len(doc.Profile.Common.Environment.Selection) > 128) {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.ExchangeVersion == ExchangeVersion && !validExchangeEnvironmentSourceShapes(data) {
		return admittedDocument{}, CodeInvalidStructure
	}
	if mcpPresent {
		if doc.ExchangeVersion != ExchangeVersion || doc.Profile.Common.MCP == nil || doc.Profile.Common.MCP.Version != commonprofile.MCPCapabilityVersion {
			return admittedDocument{}, CodeUnsupportedContent
		}
		if _, err := commonprofile.DecodeMCPSelection(doc.Profile.Common.MCP.Selection); err != nil {
			return admittedDocument{}, CodeInvalidStructure
		}
	}
	if instructionsPresent && (doc.ExchangeVersion != ExchangeVersion || doc.Profile.Common.Instructions == nil || doc.Profile.Common.Instructions.Version != 1 || doc.Profile.Common.Instructions.Selection == nil || len(doc.Profile.Common.Instructions.Selection) > instructions.MaxEntries) {
		return admittedDocument{}, CodeUnsupportedContent
	}
	if doc.Profile.Common.Workspace.Selection.Access != launch.WorkspaceAccessReadOnly && doc.Profile.Common.Workspace.Selection.Access != launch.WorkspaceAccessReadWrite {
		return admittedDocument{}, CodeInvalidStructure
	}
	if err := validateSymbolicReferences(doc.Profile.Common.Skills.Selection); err != nil {
		return admittedDocument{}, CodeUnsafePath
	}
	if doc.Profile.Common.Instructions != nil {
		if err := validateSymbolicInstructionReferences(doc.Profile.Common.Instructions.Selection); err != nil {
			return admittedDocument{}, CodeUnsafePath
		}
	}
	if code := validateDocumentRelations(&doc); code != CodeValid {
		// These are relationships within the portable document, not failures
		// of caller-supplied bindings. Do not report their semantics as passed.
		if code == CodeBindingInvalid {
			code = CodeInvalidStructure
		}
		return admittedDocument{}, code
	}
	if code := validateSymbolicIntent(doc); code != CodeValid {
		return admittedDocument{}, code
	}
	return admittedDocument{document: doc}, CodeValid
}

// validateSymbolicIntent reuses the common intent schemas with injective,
// syntax-only representatives for machine-local references. Reference kind and
// symbol identity remain distinct, so representatives neither collapse distinct
// symbols nor overlap workspace-relative/fixed-search references. These values
// are never resolved, used to create a candidate, or returned to callers.
func validateSymbolicIntent(doc document) Code {
	if len(doc.Profile.Overlays) == 0 {
		return CodeInvalidStructure
	}
	for id, overlay := range doc.Profile.Overlays {
		if overlay.Version != 1 {
			return CodeUnsupportedContent
		}
		switch id {
		case "devin":
			if overlay.AuthBinding != "" {
				return CodeUnsupportedContent
			}
		case "codex":
		default:
			return CodeUnsupportedContent
		}
	}
	// Skills and Instructions require disjoint local source kinds. A shared
	// symbol could never be satisfied, regardless of the supplied bindings.
	skillSources := map[string]bool{}
	for _, ref := range doc.Profile.Common.Skills.Selection {
		skillSources[ref.SourceBinding] = true
	}
	if doc.Profile.Common.Instructions != nil {
		for _, ref := range doc.Profile.Common.Instructions.Selection {
			if skillSources[ref.SourceBinding] {
				return CodeInvalidStructure
			}
		}
	}
	representatives := bindingDocument{Paths: map[string]string{}, Executables: map[string]string{}, Environment: map[string]string{}}
	for _, requirement := range doc.Requirements.Paths {
		representatives.Paths[requirement.ID] = "/acs-exchange-symbolic/" + requirement.ID
	}
	for _, requirement := range doc.Requirements.Executables {
		representatives.Executables[requirement.ID] = "/acs-exchange-symbolic/" + requirement.ID
	}
	for _, requirement := range doc.Requirements.Environment {
		representatives.Environment[requirement.ID] = "ACS_EXCHANGE_SYMBOLIC_" + strings.ReplaceAll(requirement.ID, "-", "_")
		representatives.Environment[requirement.ID] = strings.ToUpper(representatives.Environment[requirement.ID])
	}
	_, code := bindCommonSelections(doc, representatives)
	if code == CodeBindingInvalid {
		return CodeInvalidStructure
	}
	return code
}

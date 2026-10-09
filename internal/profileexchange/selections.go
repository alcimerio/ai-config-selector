package profileexchange

import (
	"encoding/json"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/exclusionintent"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/mcpintent"
)

type commonSelectionBytes struct {
	paths, executables, environment, mcp, exclusions json.RawMessage
}

// bindCommonSelections checks capability shape, canonical semantics, and MCP
// relationships with supplied logical reference values. It performs no resource
// lookup. Symbolic admission and actual binding share this schema boundary.
func bindCommonSelections(doc document, bindings bindingDocument) (commonSelectionBytes, Code) {
	localPathEntries := make([]commonprofile.PathEntry, 0, len(doc.Profile.Common.Paths.Selection))
	for _, entry := range doc.Profile.Common.Paths.Selection {
		localReference := commonprofile.PathReference{}
		switch entry.Reference.Kind {
		case string(launch.PathReferenceWorkspaceRelative):
			if entry.Reference.PathBinding != "" || entry.Reference.RelativePath != "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			localReference = commonprofile.PathReference{Kind: entry.Reference.Kind, Path: entry.Reference.Path}
		case "bound":
			if entry.Reference.Path != "" || entry.Reference.PathBinding == "" || entry.Reference.RelativePath != "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			localReference = commonprofile.PathReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: bindings.Paths[entry.Reference.PathBinding]}
		default:
			return commonSelectionBytes{}, CodeInvalidStructure
		}
		localPathEntries = append(localPathEntries, commonprofile.PathEntry{ID: entry.ID, Access: entry.Access, Type: entry.Type, Reference: localReference})
	}
	encodedPaths, err := commonprofile.EncodePathSelection(commonprofile.PathSelection{Entries: localPathEntries})
	if err != nil {
		return commonSelectionBytes{}, CodeBindingInvalid
	}
	var encodedExclusions json.RawMessage
	if doc.Profile.Common.Exclusions != nil {
		selection := exclusionintent.Empty()
		for _, entry := range doc.Profile.Common.Exclusions.Selection {
			ref := exclusionintent.Reference{Kind: entry.Reference.Kind, Path: entry.Reference.Path}
			switch entry.Reference.Kind {
			case "workspace-relative":
				if entry.Reference.PathBinding != "" || entry.Reference.RelativePath != "" {
					return commonSelectionBytes{}, CodeInvalidStructure
				}
			case "bound":
				if entry.Reference.Path != "" || entry.Reference.PathBinding == "" || entry.Reference.RelativePath != "" {
					return commonSelectionBytes{}, CodeInvalidStructure
				}
				ref = exclusionintent.Reference{Kind: "local-absolute", Path: bindings.Paths[entry.Reference.PathBinding]}
			default:
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			selection.Entries = append(selection.Entries, exclusionintent.Entry{ID: entry.ID, Type: exclusionintent.Type(entry.Type), Reference: ref})
		}
		encodedExclusions, err = commonprofile.EncodeExclusionSelection(selection)
		if err != nil {
			return commonSelectionBytes{}, CodeBindingInvalid
		}
	}
	localExecutableEntries := make([]commonprofile.ExecutableEntry, 0, len(doc.Profile.Common.Executables.Selection))
	for _, entry := range doc.Profile.Common.Executables.Selection {
		var reference commonprofile.ExecutableReference
		switch entry.Reference.Kind {
		case string(launch.ExecutableReferenceFixedSearchName):
			if entry.Reference.Name == "" || entry.Reference.Path != "" || entry.Reference.ExecutableBinding != "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			reference = commonprofile.ExecutableReference{Kind: entry.Reference.Kind, Name: entry.Reference.Name}
		case string(launch.ExecutableReferenceWorkspaceRelative):
			if entry.Reference.Name != "" || entry.Reference.Path == "" || entry.Reference.ExecutableBinding != "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			reference = commonprofile.ExecutableReference{Kind: entry.Reference.Kind, Path: entry.Reference.Path}
		case "bound":
			if entry.Reference.Name != "" || entry.Reference.Path != "" || entry.Reference.ExecutableBinding == "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			reference = commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceLocalAbsolute), Path: bindings.Executables[entry.Reference.ExecutableBinding]}
		default:
			return commonSelectionBytes{}, CodeInvalidStructure
		}
		localExecutableEntries = append(localExecutableEntries, commonprofile.ExecutableEntry{ID: entry.ID, Reference: reference})
	}
	encodedExecutables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: localExecutableEntries})
	if err != nil {
		return commonSelectionBytes{}, CodeBindingInvalid
	}
	localEnvironmentEntries := make([]commonprofile.EnvironmentEntry, 0, len(doc.Profile.Common.Environment.Selection))
	for _, entry := range doc.Profile.Common.Environment.Selection {
		source := commonprofile.EnvironmentSource{Kind: entry.Source.Kind}
		switch entry.Source.Kind {
		case "host-environment":
			if entry.Source.Name == "" || entry.Source.Provider != "" || entry.Source.ReferenceBinding != "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			source.Name = entry.Source.Name
		case "secret-reference":
			if entry.Source.Name != "" || entry.Source.Provider != "host-environment" || entry.Source.ReferenceBinding == "" {
				return commonSelectionBytes{}, CodeInvalidStructure
			}
			source.Provider = entry.Source.Provider
			source.Reference = bindings.Environment[entry.Source.ReferenceBinding]
		default:
			return commonSelectionBytes{}, CodeInvalidStructure
		}
		localEnvironmentEntries = append(localEnvironmentEntries, commonprofile.EnvironmentEntry{ID: entry.ID, Destination: entry.Destination, Scope: entry.Scope, Source: source, Required: entry.Required, Classification: entry.Classification})
	}
	encodedEnvironment, err := commonprofile.EncodeEnvironmentSelection(commonprofile.EnvironmentSelection{Entries: localEnvironmentEntries})
	if err != nil {
		return commonSelectionBytes{}, CodeBindingInvalid
	}
	var encodedMCP json.RawMessage
	if doc.Profile.Common.MCP != nil {
		mcpSelection, decodeErr := commonprofile.DecodeMCPSelection(doc.Profile.Common.MCP.Selection)
		if decodeErr != nil {
			return commonSelectionBytes{}, CodeInvalidStructure
		}
		localExecutables := commonprofile.ExecutableSelection{Entries: localExecutableEntries}
		localPaths := commonprofile.PathSelection{Entries: localPathEntries}
		localEnvironment := commonprofile.EnvironmentSelection{Entries: localEnvironmentEntries}
		if err := mcpintent.ValidateReferences(mcpSelection, localExecutables, localPaths, localEnvironment); err != nil {
			return commonSelectionBytes{}, CodeInvalidStructure
		}
		encodedMCP, err = commonprofile.EncodeMCPSelection(mcpSelection)
		if err != nil {
			return commonSelectionBytes{}, CodeInvalidStructure
		}
	}
	return commonSelectionBytes{paths: encodedPaths, exclusions: encodedExclusions, executables: encodedExecutables, environment: encodedEnvironment, mcp: encodedMCP}, CodeValid
}

// Package profileexchange owns the independently versioned, sanitized Profile
// exchange format. It never resolves host paths, discovers materials, or reads
// credentials.
package profileexchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const (
	ExchangeVersion            = 3
	BindingVersion             = 3
	MaxBytes                   = 1 << 20
	MaxDepth                   = 64
	maxTokens                  = 65536
	maxMembers                 = 256
	maxArray                   = 4096
	maxStringBytes             = 4096
	maxBindings                = 64
	maximumPortablePathEntries = 128
	maxPathBytes               = 1024
	maxComponents              = 128
)

type Code string

const (
	CodeValid              Code = "valid"
	CodeInvalidJSON        Code = "invalid_json"
	CodeInvalidUnicode     Code = "invalid_unicode"
	CodeDuplicateKey       Code = "duplicate_key"
	CodeLimitExceeded      Code = "limit_exceeded"
	CodeInvalidStructure   Code = "invalid_structure"
	CodeUnsupportedVersion Code = "unsupported_version"
	CodeUnsupportedContent Code = "unsupported_content"
	CodeUnsafePath         Code = "unsafe_path"
	CodeBindingRequired    Code = "binding_required"
	CodeBindingInvalid     Code = "binding_invalid"
	CodeBindingConflict    Code = "binding_conflict"
)

type Report struct {
	SourceBindings         int
	AuthenticationBindings int
	PathBindings           int
	ExecutableBindings     int
	EnvironmentBindings    int
}

type Result struct {
	Code                   Code
	Bindings               string
	SourceAvailability     string
	Authentication         string
	Runtime                string
	RequiredSources        int
	RequiredAuthentication int
	RequiredPaths          int
	RequiredExecutables    int
	RequiredEnvironment    int
	Candidate              *profile.Profile
}

type document struct {
	ExchangeVersion int             `json:"exchangeVersion"`
	Profile         exchangeProfile `json:"profile"`
	Requirements    requirements    `json:"requirements"`
}
type exchangeProfile struct {
	Common   commonIntent               `json:"common"`
	Overlays map[string]exchangeOverlay `json:"overlays"`
}
type commonIntent struct {
	Skills      exchangeSkills      `json:"skills"`
	Workspace   exchangeWorkspace   `json:"workspace"`
	Paths       exchangePaths       `json:"paths,omitempty"`
	Executables exchangeExecutables `json:"executables,omitempty"`
	Environment exchangeEnvironment `json:"environment,omitempty"`
}

type exchangeEnvironment struct {
	Version   int                        `json:"version"`
	Selection []exchangeEnvironmentEntry `json:"selection"`
}
type exchangeEnvironmentEntry struct {
	ID             string                    `json:"id"`
	Destination    string                    `json:"destination"`
	Scope          string                    `json:"scope"`
	Source         exchangeEnvironmentSource `json:"source"`
	Required       bool                      `json:"required"`
	Classification string                    `json:"classification"`
}
type exchangeEnvironmentSource struct {
	Kind             string `json:"kind"`
	Name             string `json:"name,omitempty"`
	Provider         string `json:"provider,omitempty"`
	ReferenceBinding string `json:"referenceBinding,omitempty"`
}

type exchangeExecutables struct {
	Version   int                       `json:"version"`
	Selection []exchangeExecutableEntry `json:"selection"`
}
type exchangeExecutableEntry struct {
	ID        string                      `json:"id"`
	Reference exchangeExecutableReference `json:"reference"`
}
type exchangeExecutableReference struct {
	Kind              string `json:"kind"`
	Name              string `json:"name,omitempty"`
	Path              string `json:"path,omitempty"`
	ExecutableBinding string `json:"executableBinding,omitempty"`
}

type exchangePaths struct {
	Version   int                 `json:"version"`
	Selection []exchangePathEntry `json:"selection"`
}

type exchangePathEntry struct {
	ID        string                `json:"id"`
	Access    launch.PathAccess     `json:"access"`
	Type      launch.PathType       `json:"type"`
	Reference exchangePathReference `json:"reference"`
}

type exchangePathReference struct {
	Kind         string `json:"kind"`
	Path         string `json:"path,omitempty"`
	PathBinding  string `json:"pathBinding,omitempty"`
	RelativePath string `json:"relativePath,omitempty"`
}
type exchangeSkills struct {
	Version   int                      `json:"version"`
	Selection []exchangeSkillReference `json:"selection"`
}
type exchangeSkillReference struct {
	SourceBinding string `json:"sourceBinding"`
	RelativePath  string `json:"relativePath"`
}
type exchangeWorkspace struct {
	Version   int                `json:"version"`
	Selection workspaceSelection `json:"selection"`
}
type workspaceSelection struct {
	Access launch.WorkspaceAccess `json:"access"`
}
type exchangeOverlay struct {
	Version     int    `json:"version"`
	AuthBinding string `json:"authBinding,omitempty"`
}
type requirements struct {
	Sources         []requirement `json:"sources"`
	Authentications []requirement `json:"authentications"`
	Paths           []requirement `json:"paths,omitempty"`
	Executables     []requirement `json:"executables,omitempty"`
	Environment     []requirement `json:"environment,omitempty"`
}
type requirement struct {
	ID   string `json:"id"`
	Kind string `json:"kind,omitempty"`
}
type bindingDocument struct {
	BindingVersion  int               `json:"bindingVersion"`
	Sources         map[string]string `json:"sources"`
	Authentications map[string]string `json:"authentications"`
	Paths           map[string]string `json:"paths,omitempty"`
	Executables     map[string]string `json:"executables,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

var bindingIDPattern = regexp.MustCompile(`^(source|authentication|path|executable|environment)-[1-9][0-9]{0,2}$`)

// Export encodes only understood version-3 stored intent. The caller must have
// strictly admitted the source bytes before calling Export.
func Export(candidate profile.Profile) ([]byte, Report, error) {
	if candidate.Version != profile.CurrentVersion || candidate.SourceVersion != profile.CurrentVersion {
		return nil, Report{}, errors.New("legacy Profile requires explicit migration before export")
	}
	if candidate.Target != "" || candidate.Categories != nil {
		return nil, Report{}, errors.New("unsupported Profile content")
	}
	commonIDs := make([]string, 0, len(candidate.Common))
	for id := range candidate.Common {
		commonIDs = append(commonIDs, id)
	}
	if !profileinspect.SupportsCommonV3(commonIDs) {
		return nil, Report{}, errors.New("unsupported common capability")
	}
	skillsPayload, skillsOK := candidate.Common[commonprofile.SkillsCapabilityID]
	workspacePayload, workspaceOK := candidate.Common[commonprofile.WorkspaceCapabilityID]
	if !skillsOK || !workspaceOK || skillsPayload.Version != 1 || workspacePayload.Version != 1 {
		return nil, Report{}, errors.New("unsupported common capability")
	}
	pathSelection := commonprofile.PathSelection{Entries: []commonprofile.PathEntry{}}
	if payload, ok := candidate.Common[commonprofile.PathsCapabilityID]; ok {
		if payload.Version != commonprofile.PathsCapabilityVersion {
			return nil, Report{}, errors.New("unsupported paths capability")
		}
		decodedPaths, decodeErr := commonprofile.DecodePathSelection(payload.Selection)
		if decodeErr != nil {
			return nil, Report{}, errors.New("invalid paths intent")
		}
		pathSelection = decodedPaths
	}
	executableSelection := commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{}}
	if payload, ok := candidate.Common[commonprofile.ExecutablesCapabilityID]; ok {
		if payload.Version != commonprofile.ExecutablesCapabilityVersion {
			return nil, Report{}, errors.New("unsupported executables capability")
		}
		decoded, decodeErr := commonprofile.DecodeExecutableSelection(payload.Selection)
		if decodeErr != nil {
			return nil, Report{}, errors.New("invalid executables intent")
		}
		executableSelection = decoded
	}
	environmentSelection := commonprofile.EnvironmentSelection{Entries: []commonprofile.EnvironmentEntry{}}
	if payload, ok := candidate.Common[commonprofile.EnvironmentCapabilityID]; ok {
		if payload.Version != commonprofile.EnvironmentCapabilityVersion {
			return nil, Report{}, errors.New("unsupported environment capability")
		}
		decoded, decodeErr := commonprofile.DecodeEnvironmentSelection(payload.Selection)
		if decodeErr != nil {
			return nil, Report{}, errors.New("invalid environment intent")
		}
		environmentSelection = decoded
	}
	references, err := commonprofile.DecodeSkillSelection(skillsPayload.Selection)
	if err != nil || len(references) > maxArray {
		return nil, Report{}, errors.New("invalid Skills intent")
	}
	var workspace workspaceSelection
	if err := decodeStrict(workspacePayload.Selection, &workspace); err != nil || (workspace.Access != launch.WorkspaceAccessReadOnly && workspace.Access != launch.WorkspaceAccessReadWrite) {
		return nil, Report{}, errors.New("invalid workspace intent")
	}
	sources := make([]string, 0)
	seenSource := map[string]bool{}
	for _, reference := range references {
		if !seenSource[string(reference.Source)] {
			seenSource[string(reference.Source)] = true
			sources = append(sources, string(reference.Source))
		}
	}
	sort.Strings(sources)
	sourceSymbols := make(map[string]string, len(sources))
	reqs := requirements{Sources: []requirement{}, Authentications: []requirement{}, Paths: []requirement{}, Executables: []requirement{}, Environment: []requirement{}}
	for index, source := range sources {
		symbol := fmt.Sprintf("source-%d", index+1)
		sourceSymbols[source] = symbol
		reqs.Sources = append(reqs.Sources, requirement{ID: symbol})
	}
	exchangeReferences := make([]exchangeSkillReference, 0, len(references))
	for _, reference := range references {
		exchangeReferences = append(exchangeReferences, exchangeSkillReference{SourceBinding: sourceSymbols[string(reference.Source)], RelativePath: reference.RelativePath})
	}
	sort.Slice(exchangeReferences, func(i, j int) bool {
		if exchangeReferences[i].SourceBinding != exchangeReferences[j].SourceBinding {
			return exchangeReferences[i].SourceBinding < exchangeReferences[j].SourceBinding
		}
		return exchangeReferences[i].RelativePath < exchangeReferences[j].RelativePath
	})
	if err := validateSymbolicReferences(exchangeReferences); err != nil {
		return nil, Report{}, err
	}
	exchangePathEntries := make([]exchangePathEntry, 0, len(pathSelection.Entries))
	pathBindingCount := 0
	for _, entry := range pathSelection.Entries {
		reference := exchangePathReference{Kind: entry.Reference.Kind}
		switch entry.Reference.Kind {
		case string(launch.PathReferenceWorkspaceRelative):
			reference.Path = entry.Reference.Path
		case string(launch.PathReferenceLocalAbsolute):
			pathBindingCount++
			symbol := fmt.Sprintf("path-%d", pathBindingCount)
			reference = exchangePathReference{Kind: "bound", PathBinding: symbol}
			reqs.Paths = append(reqs.Paths, requirement{ID: symbol, Kind: "local-absolute"})
		default:
			return nil, Report{}, errors.New("unsupported path reference")
		}
		exchangePathEntries = append(exchangePathEntries, exchangePathEntry{ID: entry.ID, Access: entry.Access, Type: entry.Type, Reference: reference})
	}
	exchangeExecutableEntries := make([]exchangeExecutableEntry, 0, len(executableSelection.Entries))
	executableBindingCount := 0
	for _, entry := range executableSelection.Entries {
		reference := exchangeExecutableReference{Kind: entry.Reference.Kind, Name: entry.Reference.Name, Path: entry.Reference.Path}
		if entry.Reference.Kind == string(launch.ExecutableReferenceLocalAbsolute) {
			executableBindingCount++
			symbol := fmt.Sprintf("executable-%d", executableBindingCount)
			reference = exchangeExecutableReference{Kind: "bound", ExecutableBinding: symbol}
			reqs.Executables = append(reqs.Executables, requirement{ID: symbol, Kind: "local-absolute"})
		}
		exchangeExecutableEntries = append(exchangeExecutableEntries, exchangeExecutableEntry{ID: entry.ID, Reference: reference})
	}
	exchangeEnvironmentEntries := make([]exchangeEnvironmentEntry, 0, len(environmentSelection.Entries))
	environmentBindingCount := 0
	for _, entry := range environmentSelection.Entries {
		source := exchangeEnvironmentSource{Kind: entry.Source.Kind, Name: entry.Source.Name, Provider: entry.Source.Provider}
		if entry.Source.Kind == "secret-reference" {
			environmentBindingCount++
			symbol := fmt.Sprintf("environment-%d", environmentBindingCount)
			source.ReferenceBinding = symbol
			reqs.Environment = append(reqs.Environment, requirement{ID: symbol, Kind: "host-environment-secret-reference"})
		}
		exchangeEnvironmentEntries = append(exchangeEnvironmentEntries, exchangeEnvironmentEntry{ID: entry.ID, Destination: entry.Destination, Scope: entry.Scope, Source: source, Required: entry.Required, Classification: entry.Classification})
	}
	overlays := make(map[string]exchangeOverlay, len(candidate.Overlays))
	for id, payload := range candidate.Overlays {
		if payload.Support != "" && payload.Support != "supported" {
			return nil, Report{}, errors.New("unsupported target overlay")
		}
		switch id {
		case "devin":
			if payload.Version != 1 || payload.AuthRef != "" {
				return nil, Report{}, errors.New("unsupported Devin overlay")
			}
			overlays[id] = exchangeOverlay{Version: 1}
		case "codex":
			if payload.Version != 1 {
				return nil, Report{}, errors.New("unsupported Codex overlay")
			}
			exchangePayload := exchangeOverlay{Version: 1}
			if payload.AuthRef != "" {
				if _, err := codexauth.ParseCredentialRef(payload.AuthRef); err != nil {
					return nil, Report{}, errors.New("unsupported Codex authentication reference")
				}
				exchangePayload.AuthBinding = "authentication-1"
				reqs.Authentications = append(reqs.Authentications, requirement{ID: "authentication-1", Kind: "codex-chatgpt"})
			}
			overlays[id] = exchangePayload
		default:
			return nil, Report{}, errors.New("unsupported target overlay")
		}
	}
	if len(overlays) == 0 {
		return nil, Report{}, errors.New("at least one supported target overlay is required")
	}
	doc := document{ExchangeVersion: ExchangeVersion, Profile: exchangeProfile{Common: commonIntent{
		Skills: exchangeSkills{Version: 1, Selection: exchangeReferences}, Workspace: exchangeWorkspace{Version: 1, Selection: workspace},
		Paths:       exchangePaths{Version: commonprofile.PathsCapabilityVersion, Selection: exchangePathEntries},
		Executables: exchangeExecutables{Version: commonprofile.ExecutablesCapabilityVersion, Selection: exchangeExecutableEntries},
		Environment: exchangeEnvironment{Version: commonprofile.EnvironmentCapabilityVersion, Selection: exchangeEnvironmentEntries},
	}, Overlays: overlays}, Requirements: reqs}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, Report{}, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxBytes {
		return nil, Report{}, errors.New("exchange document exceeds limit")
	}
	return encoded, Report{SourceBindings: len(reqs.Sources), AuthenticationBindings: len(reqs.Authentications), PathBindings: len(reqs.Paths), ExecutableBindings: len(reqs.Executables), EnvironmentBindings: len(reqs.Environment)}, nil
}

// Decode validates exchange and optional local binding bytes and constructs a
// candidate only after every required symbolic binding is complete.
func Decode(data, bindingData []byte, name string) Result {
	result := Result{Code: CodeInvalidStructure, Bindings: "fail", SourceAvailability: "unchecked", Authentication: "unchecked", Runtime: "unchecked"}
	if len(data) > MaxBytes {
		result.Code = CodeLimitExceeded
		return result
	}
	if code := preflight(data); code != CodeValid {
		result.Code = code
		return result
	}
	var doc document
	if err := decodeStrict(data, &doc); err != nil {
		result.Code = CodeUnsupportedContent
		return result
	}
	pathsPresent := exchangeCommonFieldPresent(data, "paths")
	executablesPresent := exchangeCommonFieldPresent(data, "executables")
	environmentPresent := exchangeCommonFieldPresent(data, "environment")
	executableRequirementsPresent := exchangeRequirementsFieldPresent(data, "executables")
	environmentRequirementsPresent := exchangeRequirementsFieldPresent(data, "environment")
	if executableRequirementsPresent && exchangeRequirementsFieldNull(data, "executables") {
		result.Code = CodeInvalidStructure
		return result
	}
	if environmentRequirementsPresent && exchangeRequirementsFieldNull(data, "environment") {
		result.Code = CodeInvalidStructure
		return result
	}
	if doc.ExchangeVersion != 1 && doc.ExchangeVersion != 2 && doc.ExchangeVersion != ExchangeVersion {
		result.Code = CodeUnsupportedVersion
		return result
	}
	if profile.ValidateName(name) != nil {
		result.Code = CodeInvalidStructure
		return result
	}
	if doc.Profile.Common.Skills.Version != 1 || doc.Profile.Common.Workspace.Version != 1 || len(doc.Profile.Common.Skills.Selection) > maxArray {
		result.Code = CodeUnsupportedContent
		return result
	}
	if doc.ExchangeVersion == 1 {
		if pathsPresent || executablesPresent || environmentPresent || executableRequirementsPresent || environmentRequirementsPresent || doc.Requirements.Paths != nil || doc.Requirements.Executables != nil || doc.Requirements.Environment != nil {
			result.Code = CodeUnsupportedContent
			return result
		}
	} else if doc.Profile.Common.Paths.Version != commonprofile.PathsCapabilityVersion || doc.Profile.Common.Paths.Selection == nil || len(doc.Profile.Common.Paths.Selection) > maximumPortablePathEntries {
		result.Code = CodeUnsupportedContent
		return result
	}
	if doc.ExchangeVersion >= 2 && executablesPresent && (doc.Profile.Common.Executables.Version != commonprofile.ExecutablesCapabilityVersion || doc.Profile.Common.Executables.Selection == nil || len(doc.Profile.Common.Executables.Selection) > 128) {
		result.Code = CodeUnsupportedContent
		return result
	}
	if doc.ExchangeVersion == 2 && (environmentPresent || environmentRequirementsPresent || doc.Requirements.Environment != nil) {
		result.Code = CodeUnsupportedContent
		return result
	}
	if doc.ExchangeVersion == ExchangeVersion && (!environmentPresent || doc.Profile.Common.Environment.Version != commonprofile.EnvironmentCapabilityVersion || doc.Profile.Common.Environment.Selection == nil || len(doc.Profile.Common.Environment.Selection) > 128) {
		result.Code = CodeUnsupportedContent
		return result
	}
	if doc.ExchangeVersion == ExchangeVersion && !validExchangeEnvironmentSourceShapes(data) {
		result.Code = CodeInvalidStructure
		return result
	}
	if doc.Profile.Common.Workspace.Selection.Access != launch.WorkspaceAccessReadOnly && doc.Profile.Common.Workspace.Selection.Access != launch.WorkspaceAccessReadWrite {
		result.Code = CodeInvalidStructure
		return result
	}
	if err := validateSymbolicReferences(doc.Profile.Common.Skills.Selection); err != nil {
		result.Code = CodeUnsafePath
		return result
	}
	if code := validateDocumentRelations(&doc); code != CodeValid {
		result.Code = code
		return result
	}
	result.RequiredSources, result.RequiredAuthentication, result.RequiredPaths, result.RequiredExecutables, result.RequiredEnvironment = len(doc.Requirements.Sources), len(doc.Requirements.Authentications), len(doc.Requirements.Paths), len(doc.Requirements.Executables), len(doc.Requirements.Environment)
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
	if err := validateLocalReferences(localReferences); err != nil {
		result.Code = CodeBindingConflict
		return result
	}
	localPathEntries := make([]commonprofile.PathEntry, 0, len(doc.Profile.Common.Paths.Selection))
	for _, entry := range doc.Profile.Common.Paths.Selection {
		localReference := commonprofile.PathReference{}
		switch entry.Reference.Kind {
		case string(launch.PathReferenceWorkspaceRelative):
			if entry.Reference.PathBinding != "" || entry.Reference.RelativePath != "" {
				result.Code = CodeInvalidStructure
				return result
			}
			localReference = commonprofile.PathReference{Kind: entry.Reference.Kind, Path: entry.Reference.Path}
		case "bound":
			if entry.Reference.Path != "" || entry.Reference.PathBinding == "" || entry.Reference.RelativePath != "" {
				result.Code = CodeInvalidStructure
				return result
			}
			localReference = commonprofile.PathReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: bindings.Paths[entry.Reference.PathBinding]}
		default:
			result.Code = CodeInvalidStructure
			return result
		}
		localPathEntries = append(localPathEntries, commonprofile.PathEntry{ID: entry.ID, Access: entry.Access, Type: entry.Type, Reference: localReference})
	}
	encodedPaths, err := commonprofile.EncodePathSelection(commonprofile.PathSelection{Entries: localPathEntries})
	if err != nil {
		result.Code = CodeBindingInvalid
		return result
	}
	localExecutableEntries := make([]commonprofile.ExecutableEntry, 0, len(doc.Profile.Common.Executables.Selection))
	for _, entry := range doc.Profile.Common.Executables.Selection {
		var reference commonprofile.ExecutableReference
		switch entry.Reference.Kind {
		case string(launch.ExecutableReferenceFixedSearchName):
			if entry.Reference.Name == "" || entry.Reference.Path != "" || entry.Reference.ExecutableBinding != "" {
				result.Code = CodeInvalidStructure
				return result
			}
			reference = commonprofile.ExecutableReference{Kind: entry.Reference.Kind, Name: entry.Reference.Name}
		case string(launch.ExecutableReferenceWorkspaceRelative):
			if entry.Reference.Name != "" || entry.Reference.Path == "" || entry.Reference.ExecutableBinding != "" {
				result.Code = CodeInvalidStructure
				return result
			}
			reference = commonprofile.ExecutableReference{Kind: entry.Reference.Kind, Path: entry.Reference.Path}
		case "bound":
			if entry.Reference.Name != "" || entry.Reference.Path != "" || entry.Reference.ExecutableBinding == "" {
				result.Code = CodeInvalidStructure
				return result
			}
			reference = commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceLocalAbsolute), Path: bindings.Executables[entry.Reference.ExecutableBinding]}
		default:
			result.Code = CodeInvalidStructure
			return result
		}
		localExecutableEntries = append(localExecutableEntries, commonprofile.ExecutableEntry{ID: entry.ID, Reference: reference})
	}
	encodedExecutables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: localExecutableEntries})
	if err != nil {
		result.Code = CodeBindingInvalid
		return result
	}
	localEnvironmentEntries := make([]commonprofile.EnvironmentEntry, 0, len(doc.Profile.Common.Environment.Selection))
	for _, entry := range doc.Profile.Common.Environment.Selection {
		source := commonprofile.EnvironmentSource{Kind: entry.Source.Kind}
		switch entry.Source.Kind {
		case "host-environment":
			if entry.Source.Name == "" || entry.Source.Provider != "" || entry.Source.ReferenceBinding != "" {
				result.Code = CodeInvalidStructure
				return result
			}
			source.Name = entry.Source.Name
		case "secret-reference":
			if entry.Source.Name != "" || entry.Source.Provider != "host-environment" || entry.Source.ReferenceBinding == "" {
				result.Code = CodeInvalidStructure
				return result
			}
			source.Provider = entry.Source.Provider
			source.Reference = bindings.Environment[entry.Source.ReferenceBinding]
		default:
			result.Code = CodeInvalidStructure
			return result
		}
		localEnvironmentEntries = append(localEnvironmentEntries, commonprofile.EnvironmentEntry{ID: entry.ID, Destination: entry.Destination, Scope: entry.Scope, Source: source, Required: entry.Required, Classification: entry.Classification})
	}
	encodedEnvironment, err := commonprofile.EncodeEnvironmentSelection(commonprofile.EnvironmentSelection{Entries: localEnvironmentEntries})
	if err != nil {
		result.Code = CodeBindingInvalid
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
	encodedWorkspace, _ := json.Marshal(workspaceSelection{Access: doc.Profile.Common.Workspace.Selection.Access})
	candidate := profile.Profile{Version: profile.CurrentVersion, SourceVersion: profile.CurrentVersion, Name: name, Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: encodedSkills}, "workspace": {Version: 1, Selection: encodedWorkspace},
	}, Overlays: overlays}
	if doc.ExchangeVersion >= 2 {
		candidate.Common[commonprofile.PathsCapabilityID] = profile.CommonPayload{Version: commonprofile.PathsCapabilityVersion, Selection: encodedPaths}
		candidate.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: commonprofile.ExecutablesCapabilityVersion, Selection: encodedExecutables}
	}
	if doc.ExchangeVersion == 3 {
		candidate.Common[commonprofile.EnvironmentCapabilityID] = profile.CommonPayload{Version: commonprofile.EnvironmentCapabilityVersion, Selection: encodedEnvironment}
	}
	result.Code, result.Bindings, result.Candidate = CodeValid, "complete", &candidate
	return result
}

func exchangeCommonFieldPresent(data []byte, field string) bool {
	var envelope struct {
		Profile struct {
			Common map[string]json.RawMessage `json:"common"`
		} `json:"profile"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	_, present := envelope.Profile.Common[field]
	return present
}

func exchangeRequirementsFieldPresent(data []byte, field string) bool {
	var envelope struct {
		Requirements map[string]json.RawMessage `json:"requirements"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	_, present := envelope.Requirements[field]
	return present
}

func exchangeRequirementsFieldNull(data []byte, field string) bool {
	var envelope struct {
		Requirements map[string]json.RawMessage `json:"requirements"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	return rawJSONNull(envelope.Requirements[field])
}

func jsonObjectFieldPresent(data []byte, field string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	_, present := object[field]
	return present
}

func jsonObjectFieldNull(data []byte, field string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	return rawJSONNull(object[field])
}

func rawJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func validExchangeEnvironmentSourceShapes(data []byte) bool {
	var envelope struct {
		Profile struct {
			Common struct {
				Environment struct {
					Selection []struct {
						Source map[string]json.RawMessage `json:"source"`
					} `json:"selection"`
				} `json:"environment"`
			} `json:"common"`
		} `json:"profile"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	for _, entry := range envelope.Profile.Common.Environment.Selection {
		kind, ok := exchangeRequiredString(entry.Source, "kind")
		if !ok {
			return false
		}
		switch kind {
		case "host-environment":
			if _, ok := exchangeRequiredString(entry.Source, "name"); !ok || len(entry.Source) != 2 {
				return false
			}
		case "secret-reference":
			provider, providerOK := exchangeRequiredString(entry.Source, "provider")
			_, referenceOK := exchangeRequiredString(entry.Source, "referenceBinding")
			if !providerOK || provider != "host-environment" || !referenceOK || len(entry.Source) != 3 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func exchangeRequiredString(fields map[string]json.RawMessage, name string) (string, bool) {
	encoded, exists := fields[name]
	if !exists {
		return "", false
	}
	var value string
	if json.Unmarshal(encoded, &value) != nil || value == "" {
		return "", false
	}
	return value, true
}

func validateDocumentRelations(doc *document) Code {
	if doc.Requirements.Sources == nil || doc.Requirements.Authentications == nil || len(doc.Requirements.Sources) > maxBindings || len(doc.Requirements.Authentications) > maxBindings || len(doc.Requirements.Paths) > maxBindings || len(doc.Requirements.Executables) > maxBindings || len(doc.Requirements.Environment) > maxBindings {
		return CodeInvalidStructure
	}
	sources, auth, paths, executables, environment := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, req := range doc.Requirements.Sources {
		if !bindingIDPattern.MatchString(req.ID) || !strings.HasPrefix(req.ID, "source-") || req.Kind != "" || sources[req.ID] {
			return CodeInvalidStructure
		}
		sources[req.ID] = true
	}
	for _, req := range doc.Requirements.Authentications {
		if !bindingIDPattern.MatchString(req.ID) || !strings.HasPrefix(req.ID, "authentication-") || req.Kind != "codex-chatgpt" || auth[req.ID] {
			return CodeInvalidStructure
		}
		auth[req.ID] = true
	}
	for _, req := range doc.Requirements.Paths {
		if !bindingIDPattern.MatchString(req.ID) || !strings.HasPrefix(req.ID, "path-") || req.Kind != "local-absolute" || paths[req.ID] {
			return CodeInvalidStructure
		}
		paths[req.ID] = true
	}
	for _, req := range doc.Requirements.Executables {
		if !bindingIDPattern.MatchString(req.ID) || !strings.HasPrefix(req.ID, "executable-") || req.Kind != "local-absolute" || executables[req.ID] {
			return CodeInvalidStructure
		}
		executables[req.ID] = true
	}
	for _, req := range doc.Requirements.Environment {
		if !bindingIDPattern.MatchString(req.ID) || !strings.HasPrefix(req.ID, "environment-") || req.Kind != "host-environment-secret-reference" || environment[req.ID] {
			return CodeInvalidStructure
		}
		environment[req.ID] = true
	}
	usedSources, usedAuth, usedPaths, usedExecutables, usedEnvironment := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, reference := range doc.Profile.Common.Skills.Selection {
		if !sources[reference.SourceBinding] {
			return CodeBindingInvalid
		}
		usedSources[reference.SourceBinding] = true
	}
	for _, payload := range doc.Profile.Overlays {
		if payload.AuthBinding != "" {
			if !auth[payload.AuthBinding] {
				return CodeBindingInvalid
			}
			usedAuth[payload.AuthBinding] = true
		}
	}
	for _, entry := range doc.Profile.Common.Paths.Selection {
		if entry.Reference.Kind == "bound" {
			if !paths[entry.Reference.PathBinding] {
				return CodeBindingInvalid
			}
			usedPaths[entry.Reference.PathBinding] = true
		}
	}
	for _, entry := range doc.Profile.Common.Executables.Selection {
		switch entry.Reference.Kind {
		case string(launch.ExecutableReferenceFixedSearchName):
			if entry.Reference.Name == "" || entry.Reference.Path != "" || entry.Reference.ExecutableBinding != "" {
				return CodeInvalidStructure
			}
		case string(launch.ExecutableReferenceWorkspaceRelative):
			if entry.Reference.Name != "" || entry.Reference.Path == "" || entry.Reference.ExecutableBinding != "" {
				return CodeInvalidStructure
			}
		case "bound":
			if !executables[entry.Reference.ExecutableBinding] {
				return CodeBindingInvalid
			}
			usedExecutables[entry.Reference.ExecutableBinding] = true
		default:
			return CodeInvalidStructure
		}
	}
	for _, entry := range doc.Profile.Common.Environment.Selection {
		switch entry.Source.Kind {
		case "host-environment":
			if entry.Source.Name == "" || entry.Source.Provider != "" || entry.Source.ReferenceBinding != "" {
				return CodeInvalidStructure
			}
		case "secret-reference":
			if entry.Source.Name != "" || entry.Source.Provider != "host-environment" || !environment[entry.Source.ReferenceBinding] {
				return CodeBindingInvalid
			}
			usedEnvironment[entry.Source.ReferenceBinding] = true
		default:
			return CodeInvalidStructure
		}
	}
	if len(usedSources) != len(sources) || len(usedAuth) != len(auth) || len(usedPaths) != len(paths) || len(usedExecutables) != len(executables) || len(usedEnvironment) != len(environment) {
		return CodeBindingInvalid
	}
	return CodeValid
}

func exactBindingKeys(requirements []requirement, values map[string]string) bool {
	if len(requirements) != len(values) {
		return false
	}
	for _, requirement := range requirements {
		if values[requirement.ID] == "" {
			return false
		}
	}
	return true
}

func validateSymbolicReferences(references []exchangeSkillReference) error {
	local := make([]skills.SkillReference, 0, len(references))
	for _, reference := range references {
		if !bindingIDPattern.MatchString(reference.SourceBinding) || !strings.HasPrefix(reference.SourceBinding, "source-") || !safeRelativePath(reference.RelativePath) {
			return errors.New("unsafe symbolic Skill Reference")
		}
		local = append(local, skills.SkillReference{Source: skills.Source(reference.SourceBinding), RelativePath: reference.RelativePath})
	}
	return validateLocalReferences(local)
}

func validateLocalReferences(references []skills.SkillReference) error {
	bundles := make([]skills.SkillBundle, 0, len(references))
	seen := map[skills.SkillReference]bool{}
	for _, reference := range references {
		if seen[reference] {
			return errors.New("duplicate Skill Reference")
		}
		seen[reference] = true
		bundles = append(bundles, skills.SkillBundle{Reference: reference})
	}
	return commonprofile.ValidateCommonDestinations(bundles)
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > maxPathBytes || strings.ContainsAny(value, "\\\x00") || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > maxComponents {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing data")
		}
		return err
	}
	return nil
}

func preflight(data []byte) Code {
	if !utf8.Valid(data) || !pairedUnicodeEscapes(data) {
		return CodeInvalidUnicode
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	tokens := 0
	if code := scanValue(decoder, 0, &tokens); code != CodeValid {
		return code
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return CodeInvalidJSON
	}
	return CodeValid
}

func scanValue(decoder *json.Decoder, depth int, tokens *int) Code {
	if depth > MaxDepth {
		return CodeLimitExceeded
	}
	token, err := decoder.Token()
	if err != nil {
		return CodeInvalidJSON
	}
	(*tokens)++
	if *tokens > maxTokens {
		return CodeLimitExceeded
	}
	if value, ok := token.(string); ok && len(value) > maxStringBytes {
		return CodeLimitExceeded
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return CodeValid
	}
	count := 0
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return CodeInvalidJSON
			}
			name, ok := key.(string)
			if !ok {
				return CodeInvalidJSON
			}
			(*tokens)++
			count++
			if *tokens > maxTokens || len(name) > maxStringBytes || count > maxMembers {
				return CodeLimitExceeded
			}
			if seen[name] {
				return CodeDuplicateKey
			}
			seen[name] = true
			if code := scanValue(decoder, depth+1, tokens); code != CodeValid {
				return code
			}
		}
	case '[':
		for decoder.More() {
			count++
			if count > maxArray {
				return CodeLimitExceeded
			}
			if code := scanValue(decoder, depth+1, tokens); code != CodeValid {
				return code
			}
		}
	default:
		return CodeInvalidJSON
	}
	if _, err := decoder.Token(); err != nil {
		return CodeInvalidJSON
	}
	return CodeValid
}

func pairedUnicodeEscapes(data []byte) bool {
	// json.Valid accepts lone UTF-16 surrogates and replaces them. Reject them
	// before typed decoding so logical identities cannot silently change.
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
		var code uint16
		for j := 1; j <= 4; j++ {
			digit := strings.IndexByte("0123456789abcdef", byte(strings.ToLower(string(data[i+j]))[0]))
			if digit < 0 {
				return false
			}
			code = code*16 + uint16(digit)
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			var low uint16
			for j := 3; j <= 6; j++ {
				b := data[i+j]
				if b >= 'A' && b <= 'F' {
					b += 'a' - 'A'
				}
				digit := strings.IndexByte("0123456789abcdef", b)
				if digit < 0 {
					return false
				}
				low = low*16 + uint16(digit)
			}
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func KnownFieldClassifications() map[string]string {
	return map[string]string{
		"version": "portable", "name": "host-bound", "target": "unsupported", "categories": "unsupported", "common": "portable",
		"common.skills.version": "portable", "common.skills.selection": "portable", "common.skills.source": "host-bound", "common.skills.relativePath": "portable",
		"common.workspace.version": "portable", "common.workspace.selection": "portable", "common.workspace.access": "portable", "overlays": "portable",
		"common.paths.version": "portable", "common.paths.selection": "portable", "common.paths.id": "portable", "common.paths.access": "portable", "common.paths.type": "portable", "common.paths.reference.kind": "portable", "common.paths.reference.path": "portable-or-symbolic",
		"common.executables.version": "portable", "common.executables.selection": "portable", "common.executables.id": "portable", "common.executables.reference.kind": "portable", "common.executables.reference.name": "portable", "common.executables.reference.path": "portable-or-symbolic",
		"common.environment.version": "portable", "common.environment.selection": "portable", "common.environment.id": "portable", "common.environment.destination": "portable", "common.environment.scope": "portable", "common.environment.required": "portable", "common.environment.classification": "portable", "common.environment.source.kind": "portable", "common.environment.source.name": "portable", "common.environment.source.provider": "portable", "common.environment.source.reference": "secret-reference-symbolic",
		"overlays.devin.version": "portable", "overlays.codex.version": "portable", "overlays.codex.authRef": "secret-reference",
		"skill-assets": "unsupported", "secret-values": "unsupported", "provider-records": "unsupported", "resolved-host-paths": "unsupported",
		"runtime-state": "unsupported", "repository-session-state": "unsupported", "unknown-fields": "unsupported",
	}
}

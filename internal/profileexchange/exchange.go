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
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const (
	ExchangeVersion = 1
	BindingVersion  = 1
	MaxBytes        = 1 << 20
	MaxDepth        = 64
	maxTokens       = 65536
	maxMembers      = 256
	maxArray        = 4096
	maxStringBytes  = 4096
	maxBindings     = 64
	maxPathBytes    = 1024
	maxComponents   = 128
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
}

type Result struct {
	Code                   Code
	Bindings               string
	SourceAvailability     string
	Authentication         string
	Runtime                string
	RequiredSources        int
	RequiredAuthentication int
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
	Skills    exchangeSkills    `json:"skills"`
	Workspace exchangeWorkspace `json:"workspace"`
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
}
type requirement struct {
	ID   string `json:"id"`
	Kind string `json:"kind,omitempty"`
}
type bindingDocument struct {
	BindingVersion  int               `json:"bindingVersion"`
	Sources         map[string]string `json:"sources"`
	Authentications map[string]string `json:"authentications"`
}

var bindingIDPattern = regexp.MustCompile(`^(source|authentication)-[1-9][0-9]{0,2}$`)

// Export encodes only understood version-3 stored intent. The caller must have
// strictly admitted the source bytes before calling Export.
func Export(candidate profile.Profile) ([]byte, Report, error) {
	if candidate.Version != profile.CurrentVersion || candidate.SourceVersion != profile.CurrentVersion {
		return nil, Report{}, errors.New("legacy Profile requires explicit migration before export")
	}
	if candidate.Target != "" || candidate.Categories != nil || len(candidate.Common) != 2 {
		return nil, Report{}, errors.New("unsupported Profile content")
	}
	skillsPayload, skillsOK := candidate.Common[commonprofile.SkillsCapabilityID]
	workspacePayload, workspaceOK := candidate.Common[commonprofile.WorkspaceCapabilityID]
	if !skillsOK || !workspaceOK || skillsPayload.Version != 1 || workspacePayload.Version != 1 {
		return nil, Report{}, errors.New("unsupported common capability")
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
	reqs := requirements{Sources: []requirement{}, Authentications: []requirement{}}
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
	doc := document{ExchangeVersion: 1, Profile: exchangeProfile{Common: commonIntent{
		Skills: exchangeSkills{Version: 1, Selection: exchangeReferences}, Workspace: exchangeWorkspace{Version: 1, Selection: workspace},
	}, Overlays: overlays}, Requirements: reqs}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, Report{}, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxBytes {
		return nil, Report{}, errors.New("exchange document exceeds limit")
	}
	return encoded, Report{SourceBindings: len(reqs.Sources), AuthenticationBindings: len(reqs.Authentications)}, nil
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
	if doc.ExchangeVersion != ExchangeVersion {
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
	result.RequiredSources, result.RequiredAuthentication = len(doc.Requirements.Sources), len(doc.Requirements.Authentications)
	if bindingData == nil {
		if result.RequiredSources+result.RequiredAuthentication != 0 {
			result.Code = CodeBindingRequired
			result.Bindings = "unresolved"
			return result
		}
		bindingData = []byte(`{"bindingVersion":1,"sources":{},"authentications":{}}`)
	}
	if len(bindingData) > MaxBytes {
		result.Code = CodeLimitExceeded
		return result
	}
	if code := preflight(bindingData); code != CodeValid {
		result.Code = code
		return result
	}
	var bindings bindingDocument
	if err := decodeStrict(bindingData, &bindings); err != nil || bindings.BindingVersion != BindingVersion || bindings.Sources == nil || bindings.Authentications == nil {
		result.Code = CodeBindingInvalid
		return result
	}
	if len(bindings.Sources) > maxBindings || len(bindings.Authentications) > maxBindings {
		result.Code = CodeLimitExceeded
		return result
	}
	if !exactBindingKeys(doc.Requirements.Sources, bindings.Sources) || !exactBindingKeys(doc.Requirements.Authentications, bindings.Authentications) {
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
	result.Code, result.Bindings, result.Candidate = CodeValid, "complete", &candidate
	return result
}

func validateDocumentRelations(doc *document) Code {
	if doc.Requirements.Sources == nil || doc.Requirements.Authentications == nil || len(doc.Requirements.Sources) > maxBindings || len(doc.Requirements.Authentications) > maxBindings {
		return CodeInvalidStructure
	}
	sources, auth := map[string]bool{}, map[string]bool{}
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
	usedSources, usedAuth := map[string]bool{}, map[string]bool{}
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
	if len(usedSources) != len(sources) || len(usedAuth) != len(auth) {
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
		"overlays.devin.version": "portable", "overlays.codex.version": "portable", "overlays.codex.authRef": "secret-reference",
		"skill-assets": "unsupported", "secret-values": "unsupported", "provider-records": "unsupported", "resolved-host-paths": "unsupported",
		"runtime-state": "unsupported", "repository-session-state": "unsupported", "unknown-fields": "unsupported",
	}
}

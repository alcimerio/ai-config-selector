// Package category owns the ordered Profile Component Category Registry.
package category

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

var categoryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Definition keeps one category's concrete selection, resolved value, and
// launch contribution types together.
type Definition[S, R any, C launch.Contribution] struct {
	ID            string
	SchemaVersion int
	Empty         func() S
	LegacyEmpty   func() S
	Encode        func(S) (json.RawMessage, error)
	Decode        func(json.RawMessage) (S, error)
	Resolve       func(context.Context, S) (R, error)
	Contribute    func(R) (C, error)
	Count         func(S) int
}

// Binding is a typed handle used by a category module to read or update its
// selection without exposing concrete types to the Registry.
type Binding[S, R any, C launch.Contribution] struct {
	registration *Registration
}

// Registration returns the type-erased registration used to assemble a
// Registry.
func (binding Binding[S, R, C]) Registration() Registration {
	return *binding.registration
}

// ID returns the stable category ID represented by this typed Binding.
func (binding Binding[S, R, C]) ID() string {
	if binding.registration == nil {
		return ""
	}
	return binding.registration.id
}

// Registration is one validated category entry accepted by NewRegistry.
type Registration struct {
	id            string
	schemaVersion int
	empty         func() any
	legacyEmpty   func() any
	encode        func(any) (json.RawMessage, error)
	decode        func(json.RawMessage) (any, error)
	resolve       func(context.Context, any) (any, error)
	contribute    func(any) (launch.Contribution, error)
	count         func(any) int
	token         *struct{ marker byte }
}

// ID returns the stable category ID represented by this opaque registration.
func (registration Registration) ID() string { return registration.id }

// SameBinding reports whether two registrations came from the same typed
// category binding. It lets application assembly validate adjacent registries
// without exposing either category values or terminal-library types.
func (registration Registration) SameBinding(other Registration) bool {
	return registration.token != nil && registration.token == other.token
}

// Bind validates a category definition and creates its typed handle.
func Bind[S, R any, C launch.Contribution](definition Definition[S, R, C]) (Binding[S, R, C], error) {
	if !categoryIDPattern.MatchString(definition.ID) {
		return Binding[S, R, C]{}, fmt.Errorf("invalid category ID %q", definition.ID)
	}
	if definition.SchemaVersion < 1 {
		return Binding[S, R, C]{}, fmt.Errorf("category %q schema version must be positive", definition.ID)
	}
	if definition.Empty == nil || definition.Resolve == nil || definition.Contribute == nil || definition.Count == nil {
		return Binding[S, R, C]{}, fmt.Errorf("category %q registration is incomplete", definition.ID)
	}
	encode := definition.Encode
	if encode == nil {
		encode = func(selection S) (json.RawMessage, error) {
			return json.Marshal(selection)
		}
	}
	decode := definition.Decode
	if decode == nil {
		decode = func(payload json.RawMessage) (S, error) {
			var selection S
			err := json.Unmarshal(payload, &selection)
			return selection, err
		}
	}

	registration := &Registration{
		id:            definition.ID,
		schemaVersion: definition.SchemaVersion,
		empty:         func() any { return definition.Empty() },
		encode: func(value any) (json.RawMessage, error) {
			selection, ok := value.(S)
			if !ok {
				return nil, fmt.Errorf("category %q selection type mismatch", definition.ID)
			}
			return encode(selection)
		},
		decode: func(payload json.RawMessage) (any, error) { return decode(payload) },
		resolve: func(ctx context.Context, value any) (any, error) {
			selection, ok := value.(S)
			if !ok {
				return nil, fmt.Errorf("category %q selection type mismatch", definition.ID)
			}
			return definition.Resolve(ctx, selection)
		},
		contribute: func(value any) (launch.Contribution, error) {
			resolved, ok := value.(R)
			if !ok {
				return nil, fmt.Errorf("category %q resolved type mismatch", definition.ID)
			}
			contribution, err := definition.Contribute(resolved)
			if err != nil {
				return nil, err
			}
			return contribution, nil
		},
		count: func(value any) int {
			selection, ok := value.(S)
			if !ok {
				return 0
			}
			return definition.Count(selection)
		},
		token: &struct{ marker byte }{marker: 1},
	}
	if definition.LegacyEmpty != nil {
		registration.legacyEmpty = func() any { return definition.LegacyEmpty() }
	}
	return Binding[S, R, C]{registration: registration}, nil
}

// Registry owns the fixed category order for one CLI Adapter.
type Registry struct {
	target       string
	requirements authority.TargetRequirements
	ordered      []*Registration
	byID         map[string]*Registration
	legacy       map[int]func([]byte) (profile.Profile, error)
}

const supportedOverlayVersion = 1

// Registrations returns the fixed category registrations in Registry order.
func (registry *Registry) Registrations() []Registration {
	if registry == nil {
		return nil
	}
	registrations := make([]Registration, len(registry.ordered))
	for index, registration := range registry.ordered {
		registrations[index] = *registration
	}
	return registrations
}

// Owns reports whether the Draft was created by this Registry.
func (registry *Registry) Owns(draft Draft) bool {
	return registry != nil && draft.registry == registry
}

// LegacyDecoder migrates one older envelope version into the current Profile
// shape before category normalization.
type LegacyDecoder struct {
	Version int
	Decode  func([]byte) (profile.Profile, error)
}

// NewRegistry validates and assembles one target's fixed category set.
func NewRegistry(target string, registrations ...Registration) (*Registry, error) {
	return NewRegistryWithLegacy(target, registrations)
}

// NewRegistryWithLegacy assembles a Registry with explicit older envelope
// decoders.
func NewRegistryWithLegacy(target string, registrations []Registration, legacyDecoders ...LegacyDecoder) (*Registry, error) {
	return NewRegistryWithRequirements(target, authority.TargetRequirements{Recipe: authority.RecipeDevin}, registrations, legacyDecoders...)
}

// NewRegistryWithRequirements assembles a Registry with fixed intrinsic
// execution requirements. Profile capabilities cannot modify these inputs.
func NewRegistryWithRequirements(target string, requirements authority.TargetRequirements, registrations []Registration, legacyDecoders ...LegacyDecoder) (*Registry, error) {
	if target == "" {
		return nil, errors.New("category Registry target is required")
	}
	if requirements.Recipe != authority.RecipeDevin && requirements.Recipe != authority.RecipeCodex {
		return nil, fmt.Errorf("category Registry target %q requires an unsupported execution recipe %q", target, requirements.Recipe)
	}
	registry := &Registry{
		target:       target,
		requirements: requirements,
		ordered:      make([]*Registration, 0, len(registrations)),
		byID:         make(map[string]*Registration, len(registrations)),
		legacy:       make(map[int]func([]byte) (profile.Profile, error), len(legacyDecoders)),
	}
	for index := range registrations {
		registration := registrations[index]
		if registration.token == nil {
			return nil, errors.New("category Registry contains an invalid registration")
		}
		if _, exists := registry.byID[registration.id]; exists {
			return nil, fmt.Errorf("duplicate category ID %q", registration.id)
		}
		entry := registration
		registry.ordered = append(registry.ordered, &entry)
		registry.byID[entry.id] = &entry
	}
	for _, decoder := range legacyDecoders {
		if decoder.Version < 1 || decoder.Version >= profile.CurrentVersion || decoder.Decode == nil {
			return nil, fmt.Errorf("invalid legacy Profile decoder for version %d", decoder.Version)
		}
		if _, exists := registry.legacy[decoder.Version]; exists {
			return nil, fmt.Errorf("duplicate legacy Profile decoder for version %d", decoder.Version)
		}
		registry.legacy[decoder.Version] = decoder.Decode
	}
	return registry, nil
}

// Draft holds typed selections for every category in Registry order.
type Draft struct {
	registry   *Registry
	selections map[string]any
}

// Summary is one category's selected-item count.
type Summary struct {
	ID    string
	Count int
}

// Clone returns an independent snapshot of every typed category selection.
// Registrations own the encoding boundary, so cloning remains category-neutral.
func (draft Draft) Clone() (Draft, error) {
	if draft.registry == nil {
		return Draft{}, errors.New("clone category Draft: uninitialized Draft")
	}
	clone := Draft{registry: draft.registry, selections: make(map[string]any, len(draft.selections))}
	for _, registration := range draft.registry.ordered {
		payload, err := registration.encode(draft.selections[registration.id])
		if err != nil {
			return Draft{}, fmt.Errorf("clone category %q selection: %w", registration.id, err)
		}
		selection, err := registration.decode(payload)
		if err != nil {
			return Draft{}, fmt.Errorf("clone category %q selection: %w", registration.id, err)
		}
		clone.selections[registration.id] = selection
	}
	return clone, nil
}

// Equal reports whether two Drafts belong to the same Registry and contain
// equal typed selections.
func (draft Draft) Equal(other Draft) bool {
	return draft.registry != nil && draft.registry == other.registry && reflect.DeepEqual(draft.selections, other.selections)
}

// NewDraft creates a draft containing every category's empty selection.
func (registry *Registry) NewDraft() Draft {
	draft := Draft{registry: registry, selections: make(map[string]any, len(registry.ordered))}
	for _, registration := range registry.ordered {
		draft.selections[registration.id] = registration.empty()
	}
	return draft
}

// DraftFromProfile seeds typed selections using the registered category decoders.
// Callers admitting stored bytes must strictly validate those same bytes first;
// this conversion neither discovers sources nor builds launch contributions.
func (registry *Registry) DraftFromProfile(candidate profile.Profile) (Draft, error) {
	normalized, err := registry.Normalize(candidate)
	if err != nil {
		return Draft{}, err
	}
	draft := registry.NewDraft()
	for _, registration := range registry.ordered {
		payload, err := registry.payloadFor(normalized, registration)
		if err != nil {
			return Draft{}, err
		}
		selection, err := registration.decode(payload.Selection)
		if err != nil {
			return Draft{}, fmt.Errorf("seed %s category: %w", registration.id, err)
		}
		draft.selections[registration.id] = selection
	}
	return draft, nil
}

// SetSelection replaces one category's selection through its typed Binding.
func SetSelection[S, R any, C launch.Contribution](draft *Draft, binding Binding[S, R, C], selection S) error {
	if draft == nil || draft.registry == nil || binding.registration == nil {
		return errors.New("set category selection: uninitialized Draft or Binding")
	}
	registered, exists := draft.registry.byID[binding.registration.id]
	if !exists || registered.token != binding.registration.token {
		return fmt.Errorf("set category selection: category %q is not registered in this Draft", binding.registration.id)
	}
	draft.selections[binding.registration.id] = selection
	return nil
}

// Selection returns one category's typed selection from a Draft.
func Selection[S, R any, C launch.Contribution](draft Draft, binding Binding[S, R, C]) (S, error) {
	var zero S
	if draft.registry == nil || binding.registration == nil {
		return zero, errors.New("get category selection: uninitialized Draft or Binding")
	}
	registered, exists := draft.registry.byID[binding.registration.id]
	if !exists || registered.token != binding.registration.token {
		return zero, fmt.Errorf("get category selection: category %q is not registered in this Draft", binding.registration.id)
	}
	selection, ok := draft.selections[binding.registration.id].(S)
	if !ok {
		return zero, fmt.Errorf("get category selection: category %q selection type mismatch", binding.registration.id)
	}
	return selection, nil
}

// Summaries reports category counts in Registry order.
func (draft Draft) Summaries() []Summary {
	if draft.registry == nil {
		return nil
	}
	summaries := make([]Summary, 0, len(draft.registry.ordered))
	for _, registration := range draft.registry.ordered {
		summaries = append(summaries, Summary{
			ID:    registration.id,
			Count: registration.count(draft.selections[registration.id]),
		})
	}
	return summaries
}

// NewProfile encodes every Draft selection into the strict version-3 common
// envelope. New Profiles default through each common capability's Empty value.
func (registry *Registry) NewProfile(name string, draft Draft) (profile.Profile, error) {
	return registry.NewProfileWithOverlay(name, draft, profile.OverlayPayload{Version: supportedOverlayVersion})
}

// NewProfileWithOverlay creates a v3 Profile with the registry's independently
// versioned target overlay. Target adapters supply only their typed payload.
func (registry *Registry) NewProfileWithOverlay(name string, draft Draft, overlay profile.OverlayPayload) (profile.Profile, error) {
	if err := profile.ValidateName(name); err != nil {
		return profile.Profile{}, err
	}
	if draft.registry != registry {
		return profile.Profile{}, errors.New("build Profile: Draft belongs to another category Registry")
	}
	if !registry.supportsCommonV3() {
		return registry.newVersionTwoProfile(name, draft, false)
	}
	candidate := profile.Profile{
		Version:       profile.CurrentVersion,
		Name:          name,
		SourceVersion: profile.CurrentVersion,
		Common:        make(map[string]profile.CommonPayload, len(registry.ordered)),
		Overlays:      map[string]profile.OverlayPayload{registry.target: overlay},
	}
	for _, registration := range registry.ordered {
		selection, err := registration.encode(draft.selections[registration.id])
		if err != nil {
			return profile.Profile{}, fmt.Errorf("encode %s category selection: %w", registration.id, err)
		}
		candidate.Common[registration.id] = profile.CommonPayload{
			Version:   registration.schemaVersion,
			Selection: selection,
		}
	}
	return candidate, nil
}

func (registry *Registry) supportsCommonV3() bool {
	_, skills := registry.byID["skills"]
	_, workspace := registry.byID["workspace"]
	return skills && workspace && len(registry.byID) == 2
}

func (registry *Registry) newVersionTwoProfile(name string, draft Draft, omitWorkspace bool) (profile.Profile, error) {
	candidate := profile.Profile{Version: profile.LegacyCurrentVersion, SourceVersion: profile.LegacyCurrentVersion, Name: name, Target: registry.target, Categories: map[string]profile.CategoryPayload{}}
	for _, registration := range registry.ordered {
		if omitWorkspace && registration.id == "workspace" {
			continue
		}
		selection, err := registration.encode(draft.selections[registration.id])
		if err != nil {
			return profile.Profile{}, fmt.Errorf("encode %s category selection: %w", registration.id, err)
		}
		candidate.Categories[registration.id] = profile.CategoryPayload{SchemaVersion: registration.schemaVersion, Selection: selection}
	}
	return candidate, nil
}

// NewLegacyProfile preserves the shipped writable v2 representation and old
// target placement for an explicitly approved edit/clone/rename of v1/v2.
// Selecting a different common authority requires explicit v3 migration.
func (registry *Registry) NewLegacyProfile(name string, draft Draft) (profile.Profile, error) {
	if err := profile.ValidateName(name); err != nil {
		return profile.Profile{}, err
	}
	if draft.registry != registry {
		return profile.Profile{}, errors.New("build legacy Profile: Draft belongs to another category Registry")
	}
	if !registry.supportsCommonV3() {
		return registry.newVersionTwoProfile(name, draft, false)
	}
	candidate := profile.Profile{Version: profile.LegacyCurrentVersion, SourceVersion: profile.LegacyCurrentVersion, Name: name, Target: registry.target, Categories: map[string]profile.CategoryPayload{}}
	for _, registration := range registry.ordered {
		if registration.id == "workspace" {
			selection, err := registration.encode(draft.selections[registration.id])
			if err != nil {
				return profile.Profile{}, err
			}
			var intent struct {
				Access launch.WorkspaceAccess `json:"access"`
			}
			if json.Unmarshal(selection, &intent) != nil || intent.Access != launch.WorkspaceAccessReadWrite {
				return profile.Profile{}, errors.New("legacy workspace authority can change only through explicit migration")
			}
			continue
		}
		selection, err := registration.encode(draft.selections[registration.id])
		if err != nil {
			return profile.Profile{}, fmt.Errorf("encode %s category selection: %w", registration.id, err)
		}
		candidate.Categories[registration.id] = profile.CategoryPayload{SchemaVersion: registration.schemaVersion, Selection: selection}
	}
	return candidate, nil
}

// Normalize validates the current Profile envelope and canonicalizes every
// category payload without changing the saved file.
func (registry *Registry) Normalize(candidate profile.Profile) (profile.Profile, error) {
	if candidate.SourceVersion == 0 {
		candidate.SourceVersion = candidate.Version
	}
	if candidate.Version != profile.CurrentVersion && candidate.Version != profile.LegacyCurrentVersion {
		return profile.Profile{}, fmt.Errorf("unsupported schema version %d", candidate.Version)
	}
	if candidate.Version == profile.LegacyCurrentVersion && candidate.Target != registry.target {
		return profile.Profile{}, fmt.Errorf("Profile %q targets %q, not %s", candidate.Name, candidate.Target, registry.target)
	}
	if candidate.Version == profile.CurrentVersion && (candidate.Target != "" || candidate.Categories != nil) {
		return profile.Profile{}, errors.New("version-3 Profile cannot contain legacy target or categories fields")
	}
	known := candidate.Categories
	if candidate.Version == profile.CurrentVersion {
		known = make(map[string]profile.CategoryPayload, len(candidate.Common))
		for id, payload := range candidate.Common {
			known[id] = profile.CategoryPayload{SchemaVersion: payload.Version, Selection: payload.Selection}
		}
	}
	for id := range known {
		registration, exists := registry.byID[id]
		if !exists {
			if candidate.Version == profile.LegacyCurrentVersion {
				return profile.Profile{}, fmt.Errorf("unknown Profile category %q", id)
			}
			return profile.Profile{}, fmt.Errorf("unknown common capability %q", id)
		}
		if candidate.Version == profile.LegacyCurrentVersion && registration.legacyEmpty != nil {
			return profile.Profile{}, fmt.Errorf("common capability %q is not valid in a legacy Profile", id)
		}
	}
	if known == nil {
		known = make(map[string]profile.CategoryPayload, len(registry.ordered))
	}
	for _, registration := range registry.ordered {
		payload, exists := known[registration.id]
		if !exists {
			if candidate.Version == profile.CurrentVersion {
				return profile.Profile{}, fmt.Errorf("missing common capability %q", registration.id)
			}
			// A LegacyEmpty registration is common-only. Its legacy value is
			// synthesized for drafts and resolution, never serialized into the
			// supported v2 categories map.
			if registration.legacyEmpty != nil {
				continue
			}
			empty := registration.empty()
			encoded, err := registration.encode(empty)
			if err != nil {
				return profile.Profile{}, fmt.Errorf("encode empty %s category selection: %w", registration.id, err)
			}
			known[registration.id] = profile.CategoryPayload{
				SchemaVersion: registration.schemaVersion,
				Selection:     encoded,
			}
			continue
		}
		if payload.SchemaVersion != registration.schemaVersion {
			return profile.Profile{}, fmt.Errorf("%s category uses unsupported schema version %d", registration.id, payload.SchemaVersion)
		}
		selection, err := registration.decode(payload.Selection)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("decode %s category selection: %w", registration.id, err)
		}
		encoded, err := registration.encode(selection)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("encode %s category selection: %w", registration.id, err)
		}
		payload.Selection = encoded
		known[registration.id] = payload
	}
	if candidate.Version == profile.CurrentVersion {
		candidate.Common = make(map[string]profile.CommonPayload, len(known))
		for id, payload := range known {
			candidate.Common[id] = profile.CommonPayload{Version: payload.SchemaVersion, Selection: payload.Selection}
		}
	} else {
		candidate.Categories = known
	}
	return candidate, nil
}

// Decode parses and normalizes a current Profile envelope.
func (registry *Registry) Decode(contents []byte) (profile.Profile, error) {
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return profile.Profile{}, err
	}
	if envelope.Version == profile.LegacyCurrentVersion {
		var candidate profile.Profile
		if err := json.Unmarshal(contents, &candidate); err != nil {
			return profile.Profile{}, err
		}
		candidate.SourceVersion = profile.LegacyCurrentVersion
		return registry.Normalize(candidate)
	}
	if envelope.Version != profile.CurrentVersion {
		decoder, exists := registry.legacy[envelope.Version]
		if !exists {
			return profile.Profile{}, fmt.Errorf("unsupported schema version %d", envelope.Version)
		}
		candidate, err := decoder(contents)
		if err != nil {
			return profile.Profile{}, err
		}
		// Legacy decoders written before v3 returned profile.CurrentVersion in
		// the target/categories shape. Admit that typed result as v2 without
		// changing the stored bytes or granting v3 defaults.
		if candidate.Version == profile.CurrentVersion && candidate.Target != "" && candidate.Categories != nil {
			candidate.Version = profile.LegacyCurrentVersion
		}
		candidate.SourceVersion = envelope.Version
		return registry.Normalize(candidate)
	}
	var candidate profile.Profile
	if err := json.Unmarshal(contents, &candidate); err != nil {
		return profile.Profile{}, err
	}
	candidate.SourceVersion = profile.CurrentVersion
	return registry.Normalize(candidate)
}

// DecodeNamed binds active decoding to the same strict exact-byte structural
// inspection used by passive commands, including duplicate and filename/body
// mismatch rejection.
func (registry *Registry) DecodeNamed(name string, contents []byte) (profile.Profile, error) {
	if !registry.supportsCommonV3() {
		return registry.Decode(contents)
	}
	entry := profileinspect.InspectBytes(name, contents)
	if entry.Status != "valid" {
		return profile.Profile{}, fmt.Errorf("%s", entry.Diagnostic.Message)
	}
	decoded, err := registry.Decode(contents)
	if err != nil {
		return profile.Profile{}, err
	}
	for _, overlay := range entry.Overlays {
		payload := decoded.Overlays[overlay.ID]
		payload.Support = overlay.Support
		decoded.Overlays[overlay.ID] = payload
	}
	return decoded, nil
}

// ResolvedProfile remains a compatibility spelling for the common immutable
// authority plan. Ownership lives in internal/authority, not an adapter.
type ResolvedProfile = authority.Plan

// Resolve validates and resolves every saved category in Registry order.
func (registry *Registry) Resolve(ctx context.Context, candidate profile.Profile) (ResolvedProfile, error) {
	return registry.ResolveFor(ctx, candidate, registry.target)
}

// ResolveFor selects exactly one supported overlay, or none for common shell
// execution. Unknown inactive overlays remain inert.
func (registry *Registry) ResolveFor(ctx context.Context, candidate profile.Profile, overlay string) (ResolvedProfile, error) {
	normalized, err := registry.Normalize(candidate)
	if err != nil {
		return ResolvedProfile{}, err
	}

	if normalized.Version == profile.CurrentVersion && overlay != "" {
		payload, exists := normalized.Overlays[overlay]
		if !exists {
			return ResolvedProfile{}, fmt.Errorf("selected target overlay %q is missing", overlay)
		}
		if overlay != registry.target || payload.Version != supportedOverlayVersion || (payload.Support != "" && payload.Support != "supported") {
			return ResolvedProfile{}, fmt.Errorf("selected target overlay %q uses unsupported version %d", overlay, payload.Version)
		}
		if overlay == "codex" && payload.AuthRef == "" {
			return ResolvedProfile{}, errors.New("selected target overlay \"codex\" requires authRef")
		}
	}
	workspaceAccess := launch.WorkspaceAccessReadWrite
	if _, ownsWorkspace := registry.byID["workspace"]; normalized.Version == profile.CurrentVersion && ownsWorkspace {
		workspace, exists := normalized.Common["workspace"]
		if !exists || workspace.Version != 1 {
			return ResolvedProfile{}, errors.New("supported common workspace intent is required")
		}
		var intent struct {
			Access launch.WorkspaceAccess `json:"access"`
		}
		decoder := json.NewDecoder(bytes.NewReader(workspace.Selection))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&intent); err != nil || (intent.Access != launch.WorkspaceAccessReadOnly && intent.Access != launch.WorkspaceAccessReadWrite) {
			return ResolvedProfile{}, errors.New("common workspace intent is invalid")
		}
		workspaceAccess = intent.Access
	}
	contributions := make([]authority.Contribution, 0, len(registry.ordered))
	for _, registration := range registry.ordered {
		payload, err := registry.payloadFor(normalized, registration)
		if err != nil {
			return ResolvedProfile{}, err
		}
		selection, err := registration.decode(payload.Selection)
		if err != nil {
			return ResolvedProfile{}, fmt.Errorf("decode %s category selection: %w", registration.id, err)
		}
		value, err := registration.resolve(ctx, selection)
		if err != nil {
			return ResolvedProfile{}, fmt.Errorf("resolve %s category selection: %w", registration.id, err)
		}
		contribution, err := registration.contribute(value)
		if err != nil {
			return ResolvedProfile{}, fmt.Errorf("build %s category launch contribution: %w", registration.id, err)
		}
		if isNilContribution(contribution) {
			return ResolvedProfile{}, fmt.Errorf("build %s category launch contribution: contribution is nil", registration.id)
		}
		contributions = append(contributions, authority.Contribution{ID: registration.id, Value: contribution})
	}
	requirements := registry.requirements
	if overlay == "" {
		requirements = authority.TargetRequirements{Recipe: authority.RecipeShell}
	}
	resolved := authority.New(contributions, workspaceAccess, normalized.SourceVersion, overlay, requirements)
	if overlay == "codex" {
		resolved = resolved.WithAuthRef(normalized.Overlays[overlay].AuthRef)
	}
	return resolved, nil
}

func (registry *Registry) payloadFor(candidate profile.Profile, registration *Registration) (profile.CategoryPayload, error) {
	if candidate.Version == profile.CurrentVersion {
		common, exists := candidate.Common[registration.id]
		if !exists {
			return profile.CategoryPayload{}, fmt.Errorf("missing common capability %q", registration.id)
		}
		return profile.CategoryPayload{SchemaVersion: common.Version, Selection: common.Selection}, nil
	}
	if payload, exists := candidate.Categories[registration.id]; exists {
		return payload, nil
	}
	if registration.legacyEmpty == nil {
		return profile.CategoryPayload{}, fmt.Errorf("missing legacy category %q", registration.id)
	}
	selection, err := registration.encode(registration.legacyEmpty())
	if err != nil {
		return profile.CategoryPayload{}, fmt.Errorf("encode legacy %s default: %w", registration.id, err)
	}
	return profile.CategoryPayload{SchemaVersion: registration.schemaVersion, Selection: selection}, nil
}

func isNilContribution(contribution launch.Contribution) bool {
	if contribution == nil {
		return true
	}
	value := reflect.ValueOf(contribution)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

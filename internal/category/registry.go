// Package category owns the ordered Profile Component Category Registry.
package category

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

var categoryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Definition keeps one category's concrete selection, resolved value, and
// launch contribution types together.
type Definition[S, R any, C launch.Contribution] struct {
	ID            string
	SchemaVersion int
	Empty         func() S
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
	encode        func(any) (json.RawMessage, error)
	decode        func(json.RawMessage) (any, error)
	resolve       func(context.Context, any) (any, error)
	contribute    func(any) (launch.Contribution, error)
	count         func(any) int
	token         *struct{ marker byte }
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
	return Binding[S, R, C]{registration: registration}, nil
}

// Registry owns the fixed category order for one CLI Adapter.
type Registry struct {
	target  string
	ordered []*Registration
	byID    map[string]*Registration
	legacy  map[int]func([]byte) (profile.Profile, error)
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
	if target == "" {
		return nil, errors.New("category Registry target is required")
	}
	registry := &Registry{
		target:  target,
		ordered: make([]*Registration, 0, len(registrations)),
		byID:    make(map[string]*Registration, len(registrations)),
		legacy:  make(map[int]func([]byte) (profile.Profile, error), len(legacyDecoders)),
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

// NewProfile encodes every Draft selection into a version-2 Profile.
func (registry *Registry) NewProfile(name string, draft Draft) (profile.Profile, error) {
	if err := profile.ValidateName(name); err != nil {
		return profile.Profile{}, err
	}
	if draft.registry != registry {
		return profile.Profile{}, errors.New("build Profile: Draft belongs to another category Registry")
	}
	candidate := profile.Profile{
		Version:    profile.CurrentVersion,
		Name:       name,
		Target:     registry.target,
		Categories: make(map[string]profile.CategoryPayload, len(registry.ordered)),
	}
	for _, registration := range registry.ordered {
		selection, err := registration.encode(draft.selections[registration.id])
		if err != nil {
			return profile.Profile{}, fmt.Errorf("encode %s category selection: %w", registration.id, err)
		}
		candidate.Categories[registration.id] = profile.CategoryPayload{
			SchemaVersion: registration.schemaVersion,
			Selection:     selection,
		}
	}
	return candidate, nil
}

// Normalize validates the current Profile envelope and canonicalizes every
// category payload without changing the saved file.
func (registry *Registry) Normalize(candidate profile.Profile) (profile.Profile, error) {
	if candidate.Version != profile.CurrentVersion {
		return profile.Profile{}, fmt.Errorf("unsupported schema version %d", candidate.Version)
	}
	if candidate.Target != registry.target {
		return profile.Profile{}, fmt.Errorf("Profile %q targets %q, not %s", candidate.Name, candidate.Target, registry.target)
	}
	for id := range candidate.Categories {
		if _, exists := registry.byID[id]; !exists {
			return profile.Profile{}, fmt.Errorf("unknown Profile category %q", id)
		}
	}
	if candidate.Categories == nil {
		candidate.Categories = make(map[string]profile.CategoryPayload, len(registry.ordered))
	}
	for _, registration := range registry.ordered {
		payload, exists := candidate.Categories[registration.id]
		if !exists {
			encoded, err := registration.encode(registration.empty())
			if err != nil {
				return profile.Profile{}, fmt.Errorf("encode empty %s category selection: %w", registration.id, err)
			}
			candidate.Categories[registration.id] = profile.CategoryPayload{
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
		candidate.Categories[registration.id] = payload
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
	if envelope.Version != profile.CurrentVersion {
		decoder, exists := registry.legacy[envelope.Version]
		if !exists {
			return profile.Profile{}, fmt.Errorf("unsupported schema version %d", envelope.Version)
		}
		candidate, err := decoder(contents)
		if err != nil {
			return profile.Profile{}, err
		}
		return registry.Normalize(candidate)
	}
	var candidate profile.Profile
	if err := json.Unmarshal(contents, &candidate); err != nil {
		return profile.Profile{}, err
	}
	return registry.Normalize(candidate)
}

// ResolvedProfile owns the ordered launch contributions produced from one
// saved Profile.
type ResolvedProfile struct {
	contributions []resolvedContribution
}

type resolvedContribution struct {
	id           string
	contribution launch.Contribution
}

// Resolve validates and resolves every saved category in Registry order.
func (registry *Registry) Resolve(ctx context.Context, candidate profile.Profile) (ResolvedProfile, error) {
	normalized, err := registry.Normalize(candidate)
	if err != nil {
		return ResolvedProfile{}, err
	}

	resolved := ResolvedProfile{contributions: make([]resolvedContribution, 0, len(registry.ordered))}
	for _, registration := range registry.ordered {
		payload := normalized.Categories[registration.id]
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
		resolved.contributions = append(resolved.contributions, resolvedContribution{id: registration.id, contribution: contribution})
	}
	return resolved, nil
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

// Plan builds one dry-run plan by applying contributions in Registry order.
func (resolved ResolvedProfile) Plan(ctx context.Context, workingDirectory string) (launch.Plan, error) {
	var plan launch.Plan
	for _, entry := range resolved.contributions {
		if err := entry.contribution.Plan(ctx, workingDirectory, &plan); err != nil {
			return launch.Plan{}, fmt.Errorf("plan %s category: %w", entry.id, err)
		}
	}
	return plan, nil
}

// Materialize applies category contributions to a Session in Registry order.
func (resolved ResolvedProfile) Materialize(sessionHome string) error {
	for _, entry := range resolved.contributions {
		if err := entry.contribution.Materialize(sessionHome); err != nil {
			return fmt.Errorf("materialize %s category: %w", entry.id, err)
		}
	}
	return nil
}

// Verify runs category verification against a materialized Session in
// Registry order.
func (resolved ResolvedProfile) Verify(ctx context.Context, verification launch.VerificationContext) error {
	for _, entry := range resolved.contributions {
		if err := entry.contribution.Verify(ctx, verification); err != nil {
			return fmt.Errorf("verify %s category: %w", entry.id, err)
		}
	}
	return nil
}

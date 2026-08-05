package builder

import (
	"context"
	"errors"
	"fmt"

	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
)

// Editor is the Bubble Tea child-model boundary implemented by each visual
// category editor. Domain packages never depend on this interface.
type Editor interface {
	tea.Model
	Draft() category.Draft
	ListFocused() bool
}

// EditorDefinition binds one visual editor and its discovery result to the
// same opaque category registration used by the domain Registry.
type EditorDefinition[D any] struct {
	ID       string
	Category category.Registration
	New      func(category.Draft) Editor
	Discover func(context.Context) (D, error)
	Loaded   func(Editor, D) (Editor, error)
}

// EditorRegistration is one type-erased visual editor registration.
type EditorRegistration struct {
	id       string
	category category.Registration
	new      func(category.Draft) Editor
	discover func(context.Context) (any, error)
	loaded   func(Editor, any) (Editor, error)
}

// RegisterEditor validates and erases one category editor while retaining its
// concrete discovery-result type inside the registration.
func RegisterEditor[D any](definition EditorDefinition[D]) (EditorRegistration, error) {
	if definition.ID == "" {
		return EditorRegistration{}, errors.New("visual editor category ID is required")
	}
	if definition.ID != definition.Category.ID() {
		return EditorRegistration{}, fmt.Errorf("mismatched visual editor registration %q for category %q", definition.ID, definition.Category.ID())
	}
	if definition.New == nil || definition.Discover == nil || definition.Loaded == nil {
		return EditorRegistration{}, fmt.Errorf("visual editor registration %q is incomplete", definition.ID)
	}
	return EditorRegistration{
		id: definition.ID, category: definition.Category, new: definition.New,
		discover: func(ctx context.Context) (any, error) { return definition.Discover(ctx) },
		loaded: func(editor Editor, discovered any) (Editor, error) {
			value, ok := discovered.(D)
			if !ok {
				return nil, fmt.Errorf("category %q discovery result type mismatch", definition.ID)
			}
			return definition.Loaded(editor, value)
		},
	}, nil
}

// EditorRegistry is the ordered, validated TUI-side counterpart of a domain
// Category Registry.
type EditorRegistry struct {
	categories    *category.Registry
	registrations []EditorRegistration
}

// NewEditorRegistry rejects incomplete or inconsistent application assembly.
func NewEditorRegistry(categories *category.Registry, registrations ...EditorRegistration) (*EditorRegistry, error) {
	if categories == nil {
		return nil, errors.New("visual editor Registry requires a category Registry")
	}
	byID := make(map[string]EditorRegistration, len(registrations))
	for _, registration := range registrations {
		if registration.id == "" || registration.new == nil || registration.discover == nil || registration.loaded == nil {
			return nil, errors.New("visual editor Registry contains an invalid registration")
		}
		if _, exists := byID[registration.id]; exists {
			return nil, fmt.Errorf("duplicate visual editor registration for category %q", registration.id)
		}
		byID[registration.id] = registration
	}

	orderedCategories := categories.Registrations()
	ordered := make([]EditorRegistration, 0, len(orderedCategories))
	for _, categoryRegistration := range orderedCategories {
		registration, exists := byID[categoryRegistration.ID()]
		if !exists {
			return nil, fmt.Errorf("missing visual editor registration for category %q", categoryRegistration.ID())
		}
		if !categoryRegistration.SameBinding(registration.category) {
			return nil, fmt.Errorf("type-incompatible visual editor registration for category %q", categoryRegistration.ID())
		}
		ordered = append(ordered, registration)
		delete(byID, categoryRegistration.ID())
	}
	for id := range byID {
		return nil, fmt.Errorf("visual editor registration %q has no matching category", id)
	}
	return &EditorRegistry{categories: categories, registrations: ordered}, nil
}

type editorSlot struct {
	registration EditorRegistration
	editor       Editor
	loadState    loadState
	loadError    error
}

func (registry *EditorRegistry) newSlots(draft category.Draft) ([]editorSlot, error) {
	if registry == nil || !registry.categories.Owns(draft) {
		return nil, errors.New("visual editor Registry and Profile Draft do not share a category Registry")
	}
	slots := make([]editorSlot, len(registry.registrations))
	for index, registration := range registry.registrations {
		editor := registration.new(draft)
		if editor == nil {
			return nil, fmt.Errorf("visual editor registration %q returned a nil editor", registration.id)
		}
		slots[index] = editorSlot{registration: registration, editor: editor, loadState: unloaded}
	}
	return slots, nil
}

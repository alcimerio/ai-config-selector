// Package profile owns Profile persistence and validation.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const (
	CurrentVersion       = 3
	LegacyCurrentVersion = 2
)

var (
	ErrInvalidProfileName = errors.New("invalid Profile name")
	profileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Profile struct {
	Version    int                        `json:"version"`
	Name       string                     `json:"name"`
	Target     string                     `json:"target,omitempty"`
	Categories map[string]CategoryPayload `json:"categories,omitempty"`
	Common     map[string]CommonPayload   `json:"common,omitempty"`
	Overlays   map[string]OverlayPayload  `json:"overlays,omitempty"`
	// SourceVersion records the admitted on-disk envelope without changing its
	// bytes. It preserves legacy grant and placement semantics after decoding.
	SourceVersion int `json:"-"`
}

type CategoryPayload struct {
	SchemaVersion int             `json:"schemaVersion"`
	Selection     json.RawMessage `json:"selection"`
}

// CommonPayload is one independently versioned common capability. Selection
// remains capability-owned and cannot grant target-specific authority.
type CommonPayload struct {
	Version   int             `json:"version"`
	Selection json.RawMessage `json:"selection"`
}

// OverlayPayload is one independently versioned, explicitly selected target
// overlay. Version one is intentionally empty and bounded.
type OverlayPayload struct {
	Version int    `json:"version"`
	AuthRef string `json:"authRef,omitempty"`
	Support string `json:"-"`
}

func ValidateName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("%w %q: use 1-64 ASCII letters, numbers, dots, underscores, or hyphens, starting with a letter or number", ErrInvalidProfileName, name)
	}
	return nil
}

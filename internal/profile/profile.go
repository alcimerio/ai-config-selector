// Package profile owns Profile persistence and validation.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// CurrentVersion is the only Profile envelope version ACS writes.
const CurrentVersion = 1

// readAliasVersion is the number this same envelope carried before the retired
// pre-common envelopes were removed and the format was renumbered to 1. It is
// accepted on read only, so Profiles and history snapshots written by earlier
// builds keep loading; every write emits CurrentVersion.
const readAliasVersion = 3

// SupportedVersion reports whether a stored envelope version denotes the
// current Profile format.
func SupportedVersion(version int) bool {
	return version == CurrentVersion || version == readAliasVersion
}

var (
	ErrInvalidProfileName = errors.New("invalid Profile name")
	profileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Profile struct {
	Version  int                       `json:"version"`
	Name     string                    `json:"name"`
	Common   map[string]CommonPayload  `json:"common,omitempty"`
	Overlays map[string]OverlayPayload `json:"overlays,omitempty"`
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

// MarshalJSON preserves the required overlays object even for a common-only
// Profile.
func (p Profile) MarshalJSON() ([]byte, error) {
	type stored Profile
	if p.Overlays == nil || len(p.Overlays) != 0 {
		return json.Marshal(stored(p))
	}
	overlays := p.Overlays
	return json.Marshal(struct {
		stored
		Overlays map[string]OverlayPayload `json:"overlays"`
	}{stored: stored(p), Overlays: overlays})
}

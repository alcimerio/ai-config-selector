// Package profile owns Profile persistence and validation.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const CurrentVersion = 2

var (
	ErrInvalidProfileName = errors.New("invalid Profile name")
	profileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Profile struct {
	Version    int                        `json:"version"`
	Name       string                     `json:"name"`
	Target     string                     `json:"target"`
	Categories map[string]CategoryPayload `json:"categories"`
}

type CategoryPayload struct {
	SchemaVersion int             `json:"schemaVersion"`
	Selection     json.RawMessage `json:"selection"`
}

func ValidateName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("%w %q: use 1-64 ASCII letters, numbers, dots, underscores, or hyphens, starting with a letter or number", ErrInvalidProfileName, name)
	}
	return nil
}

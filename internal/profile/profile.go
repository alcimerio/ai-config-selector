// Package profile owns Profile persistence and validation.
package profile

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const CurrentVersion = 1

var (
	ErrInvalidProfileName = errors.New("invalid Profile name")
	profileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Profile struct {
	Version         int                     `json:"version"`
	Name            string                  `json:"name"`
	Target          string                  `json:"target"`
	SkillReferences []skills.SkillReference `json:"skillReferences"`
}

func ValidateName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("%w %q: use 1-64 ASCII letters, numbers, dots, underscores, or hyphens, starting with a letter or number", ErrInvalidProfileName, name)
	}
	return nil
}

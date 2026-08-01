// Package launch contains the CLI-neutral description of an ACS launch.
package launch

import (
	"io"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// Plan describes what ACS would materialize and what Devin may inherit from
// the current project without creating a Session.
type Plan struct {
	SelectedGlobalSkillBundles []SelectedGlobalSkillBundle
	ProjectLocalSkillBundles   []ProjectLocalSkillBundle
}

type SelectedGlobalSkillBundle struct {
	Bundle      skills.SkillBundle
	SessionPath string
}

type ProjectLocalSkillBundle struct {
	DisplayName string
	BundlePath  string
}

// Terminal is the invoking terminal connection inherited by a launched CLI.
type Terminal struct {
	Input       io.Reader
	Output      io.Writer
	ErrorOutput io.Writer
}

// Package launch contains the CLI-neutral description of an ACS launch.
package launch

import (
	"context"
	"io"
)

// Contribution is one resolved Profile Component Category's ordered input to
// dry-run planning, Session materialization, and launch verification.
type Contribution interface {
	Plan(context.Context, string, *Plan) error
	Materialize(sessionHome string) error
	Verify(context.Context, VerificationContext) error
}

// VerificationContext is the target process environment visible to category
// verification after Session materialization.
type VerificationContext struct {
	SessionsDirectory  string
	SessionDirectory   string
	SessionHome        string
	TemporaryDirectory string
	WorkingDirectory   string
}

// Plan describes what ACS would materialize and what the target CLI may
// inherit from the current project without creating a Session.
type Plan struct {
	Sections []PlanSection
}

// PlanSection is one category's declarative dry-run output group.
type PlanSection struct {
	Title string
	Items []PlanItem
}

// PlanItem is one planned item with optional labeled details.
type PlanItem struct {
	Label   string
	Details []PlanDetail
}

// PlanDetail is one labeled value rendered under a planned item.
type PlanDetail struct {
	Label string
	Value string
}

// Terminal is the invoking terminal connection inherited by a launched CLI.
type Terminal struct {
	Input       io.Reader
	Output      io.Writer
	ErrorOutput io.Writer
}

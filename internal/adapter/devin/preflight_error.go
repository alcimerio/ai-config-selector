package devin

import "fmt"

type Capability string

const (
	CapabilitySkillIsolation Capability = "skill isolation"
	CapabilityAuthentication Capability = "authentication"
)

type preflightFailureReason uint8

const (
	reasonInspectionFailed preflightFailureReason = iota + 1
	reasonCatalogMismatch
	reasonAuthenticationUnavailable
)

// PreflightError is safe to present to users. It never includes subprocess
// output, environment values, credential contents, or account details.
type PreflightError struct {
	Capability Capability
	Expected   []string
	Observed   []string
	reason     preflightFailureReason
}

func (e *PreflightError) Error() string {
	switch e.reason {
	case reasonInspectionFailed:
		return "Devin Adapter Preflight failed: skill isolation could not be inspected; verify the installed Devin CLI supports `devin skills list --json`"
	case reasonCatalogMismatch:
		return fmt.Sprintf("Devin Adapter Preflight failed: skill isolation could not be verified (expected global Skill Catalog %v; observed %v); the installed Devin CLI is incompatible with ACS isolation", e.Expected, e.Observed)
	case reasonAuthenticationUnavailable:
		return "Devin Adapter Preflight failed: usable existing authentication could not be verified; run `devin auth login` outside ACS and retry"
	default:
		return "Devin Adapter Preflight failed"
	}
}

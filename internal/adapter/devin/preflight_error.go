package devin

import "fmt"

type Capability string

const (
	CapabilitySkillIsolation Capability = "skill isolation"
	CapabilityAuthentication Capability = "authentication"
)

type preflightFailureReason uint8

const (
	reasonExecutableUnavailable preflightFailureReason = iota + 1
	reasonVerificationInterrupted
	reasonSkillInspectionCommandFailed
	reasonSkillInspectionOutputInvalid
	reasonCatalogMismatch
	reasonAuthenticationCommandFailed
	reasonAuthenticationUnavailable
)

// PreflightError is safe to present to users. It never includes subprocess
// output, environment values, credential contents, or account details.
type PreflightError struct {
	Capability Capability
	reason     preflightFailureReason
}

func (e *PreflightError) Error() string {
	switch e.reason {
	case reasonExecutableUnavailable:
		return "Devin Adapter Preflight failed: the Devin executable could not be started; verify Devin is installed and the configured executable path is valid"
	case reasonVerificationInterrupted:
		return fmt.Sprintf("Devin Adapter Preflight failed: %s verification was canceled or timed out; retry with a live Session", e.Capability)
	case reasonSkillInspectionCommandFailed:
		return "Devin Adapter Preflight failed: the skill isolation probe failed; run `devin skills list --json` outside ACS and resolve the reported CLI error"
	case reasonSkillInspectionOutputInvalid:
		return "Devin Adapter Preflight failed: Devin returned an incompatible global Skill Catalog response; update Devin or ACS before retrying"
	case reasonCatalogMismatch:
		return "Devin Adapter Preflight failed: skill isolation could not be verified because the global Skill Catalog did not match; the installed Devin CLI is incompatible with ACS isolation"
	case reasonAuthenticationCommandFailed:
		return "Devin Adapter Preflight failed: the authentication probe failed; run `devin auth status` outside ACS and resolve the reported CLI error"
	case reasonAuthenticationUnavailable:
		return "Devin Adapter Preflight failed: usable existing authentication could not be verified; run `devin auth login` outside ACS and retry"
	default:
		return "Devin Adapter Preflight failed"
	}
}

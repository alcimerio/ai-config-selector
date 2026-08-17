package devin

type Capability string

const (
	CapabilitySkillIsolation Capability = "skill isolation"
	CapabilityAuthentication Capability = "authentication"
)

// PreflightErrorCategory is a stable, redacted class of existing-Devin
// capability failure. It deliberately does not include command output,
// account data, credentials, paths, or environment entries.
type PreflightErrorCategory string

const (
	SkillPreflightFailed          PreflightErrorCategory = "skill_preflight_failed"
	AuthenticationPreflightFailed PreflightErrorCategory = "authentication_preflight_failed"
	DevinPreflightFailed          PreflightErrorCategory = "devin_preflight_failed"
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

const requiredSandboxNotice = "ACS will not start Devin without the required sandbox"

func (e *PreflightError) Category() PreflightErrorCategory {
	if e == nil {
		return DevinPreflightFailed
	}
	switch e.Capability {
	case CapabilitySkillIsolation:
		return SkillPreflightFailed
	case CapabilityAuthentication:
		return AuthenticationPreflightFailed
	default:
		return DevinPreflightFailed
	}
}

func (e *PreflightError) Error() string {
	prefix := string(e.Category()) + ": Devin Adapter Preflight failed: "
	message := ""
	switch e.reason {
	case reasonExecutableUnavailable:
		message = "the Devin executable could not be started; verify Devin is installed and the configured executable path is valid"
	case reasonVerificationInterrupted:
		message = "verification was canceled or timed out; retry with a live Session"
	case reasonSkillInspectionCommandFailed:
		message = "the skill isolation probe failed; run `devin skills list --json` outside ACS and resolve the reported CLI error"
	case reasonSkillInspectionOutputInvalid:
		message = "Devin returned an incompatible global Skill Catalog response; update Devin or ACS before retrying"
	case reasonCatalogMismatch:
		message = "skill isolation could not be verified because the global Skill Catalog did not match; the installed Devin CLI is incompatible with ACS isolation"
	case reasonAuthenticationCommandFailed:
		message = "the authentication probe failed; run `devin auth status` outside ACS and resolve the reported CLI error"
	case reasonAuthenticationUnavailable:
		message = "usable existing authentication could not be verified; run `devin auth login` outside ACS and retry"
	default:
		message = "preflight could not be completed"
	}
	return prefix + message + "; " + requiredSandboxNotice
}

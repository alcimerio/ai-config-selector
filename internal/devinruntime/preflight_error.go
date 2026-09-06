package devinruntime

// Capability identifies a redacted runtime capability check.
type Capability string

const (
	CapabilitySkillIsolation Capability = "skill isolation"
	CapabilityAuthentication Capability = "authentication"
)

// PreflightErrorCategory is a stable, redacted class of existing-Devin
// capability failure. It deliberately excludes command output, account data,
// credentials, paths, and environment entries.
type PreflightErrorCategory string

const (
	SkillPreflightFailed          PreflightErrorCategory = "skill_preflight_failed"
	AuthenticationPreflightFailed PreflightErrorCategory = "authentication_preflight_failed"
	DevinPreflightFailed          PreflightErrorCategory = "devin_preflight_failed"
)

// PreflightFailureReason is an internal runtime interpretation reason. Its
// values are deliberately not included in user-facing diagnostics.
type PreflightFailureReason uint8

const (
	ReasonExecutableUnavailable PreflightFailureReason = iota + 1
	ReasonVerificationInterrupted
	ReasonSkillInspectionCommandFailed
	ReasonSkillInspectionOutputInvalid
	ReasonCatalogMismatch
	ReasonAuthenticationCommandFailed
	ReasonAuthenticationUnavailable
)

// PreflightError is safe to present to users. It never includes subprocess
// output, environment values, credential contents, or account details.
type PreflightError struct {
	Capability Capability
	reason     PreflightFailureReason
}

// NewPreflightError creates a redacted runtime capability failure.
func NewPreflightError(capability Capability, reason PreflightFailureReason) *PreflightError {
	return &PreflightError{Capability: capability, reason: reason}
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
	case ReasonExecutableUnavailable:
		message = "the Devin executable could not be started; verify Devin is installed and the configured executable path is valid"
	case ReasonVerificationInterrupted:
		message = "verification was canceled or timed out; retry with a live Session"
	case ReasonSkillInspectionCommandFailed:
		message = "the skill isolation probe failed; run `devin skills list --json` outside ACS and resolve the reported CLI error"
	case ReasonSkillInspectionOutputInvalid:
		message = "Devin returned an incompatible global Skill Catalog response; update Devin or ACS before retrying"
	case ReasonCatalogMismatch:
		message = "skill isolation could not be verified because the global Skill Catalog did not match; the installed Devin CLI is incompatible with ACS isolation"
	case ReasonAuthenticationCommandFailed:
		message = "the authentication probe failed; run `devin auth status` outside ACS and resolve the reported CLI error"
	case ReasonAuthenticationUnavailable:
		message = "usable existing authentication could not be verified; run `devin auth login` outside ACS and retry"
	default:
		message = "preflight could not be completed"
	}
	return prefix + message + "; " + requiredSandboxNotice
}

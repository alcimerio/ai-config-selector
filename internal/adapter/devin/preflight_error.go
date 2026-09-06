package devin

import "github.com/alcimerio/ai-config-selector/internal/devinruntime"

type Capability = devinruntime.Capability

const (
	CapabilitySkillIsolation = devinruntime.CapabilitySkillIsolation
	CapabilityAuthentication = devinruntime.CapabilityAuthentication
)

// PreflightErrorCategory is a stable, redacted class of existing-Devin
// capability failure. It deliberately does not include command output,
// account data, credentials, paths, or environment entries.
type PreflightErrorCategory = devinruntime.PreflightErrorCategory

const (
	SkillPreflightFailed          = devinruntime.SkillPreflightFailed
	AuthenticationPreflightFailed = devinruntime.AuthenticationPreflightFailed
	DevinPreflightFailed          = devinruntime.DevinPreflightFailed
)

type preflightFailureReason = devinruntime.PreflightFailureReason

const (
	reasonExecutableUnavailable        = devinruntime.ReasonExecutableUnavailable
	reasonVerificationInterrupted      = devinruntime.ReasonVerificationInterrupted
	reasonSkillInspectionCommandFailed = devinruntime.ReasonSkillInspectionCommandFailed
	reasonSkillInspectionOutputInvalid = devinruntime.ReasonSkillInspectionOutputInvalid
	reasonCatalogMismatch              = devinruntime.ReasonCatalogMismatch
	reasonAuthenticationCommandFailed  = devinruntime.ReasonAuthenticationCommandFailed
	reasonAuthenticationUnavailable    = devinruntime.ReasonAuthenticationUnavailable
)

// PreflightError remains the Devin Adapter's compatibility error shape while
// delegating its redacted category and diagnostic mapping to devinruntime.
type PreflightError struct {
	Capability Capability
	reason     preflightFailureReason
	runtime    *devinruntime.PreflightError
}

func (e *PreflightError) Category() PreflightErrorCategory {
	if e == nil {
		return devinruntime.NewPreflightError("", 0).Category()
	}
	if e.runtime != nil {
		return e.runtime.Category()
	}
	return devinruntime.NewPreflightError(e.Capability, e.reason).Category()
}

func (e *PreflightError) Error() string {
	if e == nil {
		return devinruntime.NewPreflightError("", 0).Error()
	}
	if e.runtime != nil {
		return e.runtime.Error()
	}
	return devinruntime.NewPreflightError(e.Capability, e.reason).Error()
}

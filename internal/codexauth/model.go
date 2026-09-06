// Package codexauth owns ACS-managed named Codex authentication identities.
package codexauth

import "github.com/alcimerio/ai-config-selector/internal/codexauthresource"

const (
	SupportedCodexVersion = codexauthresource.SupportedCodexVersion
)

var (
	ErrInvalidCredentialRef  = codexauthresource.ErrInvalidCredentialRef
	ErrIdentityExists        = codexauthresource.ErrIdentityExists
	ErrIdentityNotFound      = codexauthresource.ErrIdentityNotFound
	ErrIdentityBusy          = codexauthresource.ErrIdentityBusy
	ErrProviderUnavailable   = codexauthresource.ErrProviderUnavailable
	ErrLoginFailed           = codexauthresource.ErrLoginFailed
	ErrLoginCleanupUncertain = codexauthresource.ErrLoginCleanupUncertain
	ErrUnsupportedVersion    = codexauthresource.ErrUnsupportedVersion
	ErrUnsupportedAuth       = codexauthresource.ErrUnsupportedAuth
	ErrStatusFailed          = codexauthresource.ErrStatusFailed
	ErrProjectedAuthInvalid  = codexauthresource.ErrProjectedAuthInvalid
	ErrBindingQuarantined    = codexauthresource.ErrBindingQuarantined
)

// CredentialRef is the canonical, secret-free name of one ACS-owned Codex
// authentication identity. It never contains credential bytes.
type CredentialRef = codexauthresource.CredentialRef

// ParseCredentialRef validates a canonical identity name. Names are lowercase
// so filesystem locks and Keychain account names have one unambiguous form.
func ParseCredentialRef(value string) (CredentialRef, error) {
	return codexauthresource.ParseCredentialRef(value)
}

// LoginMethod is the validated authentication mechanism represented by an
// identity. The first implementation deliberately accepts ChatGPT login only.
type LoginMethod = codexauthresource.LoginMethod

const LoginMethodChatGPT = codexauthresource.LoginMethodChatGPT

// IdentityMetadata is the non-secret portion of one durable identity.
type IdentityMetadata = codexauthresource.IdentityMetadata

// BindingDisposition is the terminal, secret-free outcome of one projected
// identity lifecycle.
type BindingDisposition = codexauthresource.BindingDisposition

const (
	CommittedSameIdentityRefresh = codexauthresource.CommittedSameIdentityRefresh
	DiscardedProjection          = codexauthresource.DiscardedProjection
	QuarantinedUncertain         = codexauthresource.QuarantinedUncertain
)

// IdentityStatus reports only durable metadata and the binding disposition.
type IdentityStatus = codexauthresource.IdentityStatus

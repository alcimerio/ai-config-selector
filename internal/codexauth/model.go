// Package codexauth owns ACS-managed named Codex authentication identities.
package codexauth

import (
	"errors"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
)

const (
	SupportedCodexVersion = "0.149.1"
	recordVersion         = codexauthresource.RecordVersion
)

var (
	ErrInvalidCredentialRef  = codexauthresource.ErrInvalidCredentialRef
	ErrIdentityExists        = codexauthresource.ErrIdentityExists
	ErrIdentityNotFound      = codexauthresource.ErrIdentityNotFound
	ErrIdentityBusy          = codexauthresource.ErrIdentityBusy
	ErrProviderUnavailable   = codexauthresource.ErrProviderUnavailable
	ErrLoginFailed           = errors.New("contained Codex login failed")
	ErrLoginCleanupUncertain = errors.New("contained Codex login cleanup is uncertain")
	ErrUnsupportedVersion    = errors.New("unsupported Codex CLI version")
	ErrUnsupportedAuth       = codexauthresource.ErrUnsupportedAuth
	ErrStatusFailed          = errors.New("contained Codex authentication status failed")
	ErrProjectedAuthInvalid  = errors.New("projected Codex authentication changed identity or became invalid")
	ErrBindingQuarantined    = errors.New("Codex authentication binding is quarantined")
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
type IdentityStatus struct {
	Metadata    IdentityMetadata
	Disposition BindingDisposition
}

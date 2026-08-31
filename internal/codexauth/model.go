// Package codexauth owns ACS-managed named Codex authentication identities.
package codexauth

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	SupportedCodexVersion = "0.149.1"
	recordVersion         = 1
)

var (
	ErrInvalidCredentialRef  = errors.New("invalid Codex authentication identity name")
	ErrIdentityExists        = errors.New("Codex authentication identity already exists")
	ErrIdentityNotFound      = errors.New("Codex authentication identity does not exist")
	ErrIdentityBusy          = errors.New("Codex authentication identity is in use")
	ErrProviderUnavailable   = errors.New("Codex authentication provider is unavailable")
	ErrLoginFailed           = errors.New("contained Codex login failed")
	ErrLoginCleanupUncertain = errors.New("contained Codex login cleanup is uncertain")
	ErrUnsupportedVersion    = errors.New("unsupported Codex CLI version")
	ErrUnsupportedAuth       = errors.New("unsupported Codex authentication data")
	ErrStatusFailed          = errors.New("contained Codex authentication status failed")
	ErrProjectedAuthInvalid  = errors.New("projected Codex authentication changed identity or became invalid")
	ErrBindingQuarantined    = errors.New("Codex authentication binding is quarantined")

	credentialRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// CredentialRef is the canonical, secret-free name of one ACS-owned Codex
// authentication identity. It never contains credential bytes.
type CredentialRef string

// ParseCredentialRef validates a canonical identity name. Names are lowercase
// so filesystem locks and Keychain account names have one unambiguous form.
func ParseCredentialRef(value string) (CredentialRef, error) {
	if !credentialRefPattern.MatchString(value) {
		return "", fmt.Errorf("%w %q: use 1-64 lowercase ASCII letters, numbers, dots, underscores, or hyphens, starting with a letter or number", ErrInvalidCredentialRef, value)
	}
	return CredentialRef(value), nil
}

// LoginMethod is the validated authentication mechanism represented by an
// identity. The first implementation deliberately accepts ChatGPT login only.
type LoginMethod string

const LoginMethodChatGPT LoginMethod = "chatgpt"

// IdentityMetadata is the non-secret portion of one durable identity.
type IdentityMetadata struct {
	Name        CredentialRef `json:"name"`
	Method      LoginMethod   `json:"method"`
	Workspace   string        `json:"workspace,omitempty"`
	Fingerprint string        `json:"fingerprint"`
}

// BindingDisposition is the terminal, secret-free outcome of one projected
// identity lifecycle.
type BindingDisposition string

const (
	CommittedSameIdentityRefresh BindingDisposition = "committed_same_identity_refresh"
	DiscardedProjection          BindingDisposition = "discarded_projection"
	QuarantinedUncertain         BindingDisposition = "quarantined_uncertain"
)

// IdentityStatus reports only durable metadata and the binding disposition.
type IdentityStatus struct {
	Metadata    IdentityMetadata
	Disposition BindingDisposition
}

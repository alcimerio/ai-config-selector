package codexauthresource

import (
	"context"
	"errors"
	"fmt"
)

// ProviderID names an identity namespace, never an automatic fallback order.
type ProviderID string

const (
	ProviderKeychain      ProviderID = "keychain"
	ProviderFile          ProviderID = "file"
	ProviderSecretService ProviderID = "secret-service"
)

var (
	ErrProviderNotSelected = fmt.Errorf("%w: select a credential provider explicitly", ErrProviderUnavailable)
	ErrProviderChoice      = fmt.Errorf("%w: invalid credential provider choice", ErrProviderUnavailable)
	ErrProviderConflict    = fmt.Errorf("%w: a different credential provider is already selected", ErrProviderUnavailable)
)

// newPlatformProvider preserves lazy failure: unrelated commands may construct
// a Store, but no credential operation can succeed without its chosen provider.
func newPlatformProvider() credentialProvider {
	id, err := SelectedProvider()
	if err != nil {
		return unavailableProvider{err: err}
	}
	return newCredentialProvider(id)
}

// unavailableProvider never interprets absence or failure as an empty store.
type unavailableProvider struct{ err error }

func (provider unavailableProvider) failure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if errors.Is(provider.err, ErrProviderUnavailable) {
		return provider.err
	}
	return ErrProviderUnavailable
}

func (provider unavailableProvider) Metadata(ctx context.Context, _ CredentialRef) (IdentityMetadata, bool, error) {
	return IdentityMetadata{}, false, provider.failure(ctx)
}
func (provider unavailableProvider) Create(ctx context.Context, _ credentialRecord) error {
	return provider.failure(ctx)
}
func (provider unavailableProvider) Replace(ctx context.Context, _ credentialRecord) error {
	return provider.failure(ctx)
}
func (provider unavailableProvider) List(ctx context.Context) ([]IdentityMetadata, error) {
	return nil, provider.failure(ctx)
}
func (provider unavailableProvider) Load(ctx context.Context, _ CredentialRef) (credentialRecord, bool, error) {
	return credentialRecord{}, false, provider.failure(ctx)
}
func (provider unavailableProvider) Delete(ctx context.Context, _ CredentialRef) error {
	return provider.failure(ctx)
}

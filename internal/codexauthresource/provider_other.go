//go:build !darwin && !linux

package codexauthresource

func SelectedProvider() (ProviderID, error) { return "", ErrProviderUnavailable }
func SelectProvider(ProviderID) error       { return ErrProviderUnavailable }
func newCredentialProvider(ProviderID) credentialProvider {
	return unavailableProvider{err: ErrProviderUnavailable}
}

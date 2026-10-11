package codexauthresource

// SelectedProvider retains the existing macOS Keychain namespace. Linux/XDG
// configuration cannot change where existing macOS identities are stored.
func SelectedProvider() (ProviderID, error) { return ProviderKeychain, nil }

// SelectProvider cannot migrate or replace the macOS Keychain namespace.
func SelectProvider(id ProviderID) error {
	if id != ProviderKeychain {
		return ErrProviderChoice
	}
	return nil
}

func newCredentialProvider(id ProviderID) credentialProvider {
	if id == ProviderKeychain {
		return newKeychainProvider()
	}
	return unavailableProvider{err: ErrProviderChoice}
}

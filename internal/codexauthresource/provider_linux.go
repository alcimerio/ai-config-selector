package codexauthresource

import (
	"os"
	"path/filepath"
)

// SelectedProvider reads the explicit durable Linux choice. Missing or invalid
// configuration is an error, including on headless hosts without a desktop bus.
func SelectedProvider() (ProviderID, error) {
	path, err := providerConfigDirectory()
	if err != nil {
		return "", err
	}
	return readProviderSelection(path)
}

// SelectProvider persists a choice, not credentials. It is create-only:
// switching namespaces requires a separately reviewed migration workflow.
func SelectProvider(id ProviderID) error {
	if id != ProviderFile && id != ProviderSecretService {
		return ErrProviderChoice
	}
	path, err := providerConfigDirectory()
	if err != nil {
		return err
	}
	return writeProviderSelection(path, id)
}

func providerConfigDirectory() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", ErrProviderChoice
		}
		base = filepath.Join(home, ".config")
	}
	if !filepath.IsAbs(base) {
		return "", ErrProviderChoice
	}
	return filepath.Join(base, "acs"), nil
}

func newCredentialProvider(id ProviderID) credentialProvider {
	if id == ProviderFile {
		return newFileCredentialProvider()
	}
	if id != ProviderFile && id != ProviderSecretService {
		return unavailableProvider{err: ErrProviderChoice}
	}
	// Secret Service has no implementation or fallback. Linux launch admission
	// remains independently closed, including when file storage is selected.
	return unavailableProvider{err: ErrProviderUnavailable}
}

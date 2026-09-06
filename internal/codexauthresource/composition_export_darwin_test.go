//go:build darwin

package codexauthresource

import "testing"

// UseIsolatedTestKeychainForComposition is compiled only into this package's
// native test binary so external composition tests can share the credential-
// free disposable Keychain without exposing a production backend constructor.
func UseIsolatedTestKeychainForComposition(t *testing.T) {
	t.Helper()
	useIsolatedTestKeychain(t)
}

// PrepareIsolatedKeychainRecordForComposition returns the exact production
// metadata and payload encoding for a synthetic record used only by native
// composition tests. It does not write or select a provider.
func PrepareIsolatedKeychainRecordForComposition(name CredentialRef, auth []byte) (string, []byte, error) {
	metadata, err := validateAuthJSON(name, auth)
	if err != nil {
		return "", nil, err
	}
	comment, err := encodeMetadata(metadata)
	if err != nil {
		return "", nil, err
	}
	payload, err := encodeEnvelope(auth)
	if err != nil {
		return "", nil, err
	}
	return comment, payload, nil
}

// KeychainServiceForComposition exposes only the non-secret service label to
// external native composition tests; it is absent from production builds.
func KeychainServiceForComposition() string { return keychainService }

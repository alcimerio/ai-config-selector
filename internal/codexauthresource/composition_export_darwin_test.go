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

//go:build darwin

package codexauthresource

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// UseIsolatedTestKeychainForComposition is compiled only into this package's
// native test binary so external composition tests can share the credential-
// free disposable Keychain without exposing a production backend constructor.
func UseIsolatedTestKeychainForComposition(t *testing.T) {
	t.Helper()
	useIsolatedTestKeychain(t)
}

// UseTestIdentityForComposition provides signed credentials and their test-only
// verification keys without changing the production constructor.
func UseTestIdentityForComposition(t *testing.T, store *Store) []byte {
	t.Helper()
	store.verifier = newTestIDTokenVerifier(t)
	auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
	auth = bytes.Replace(auth, []byte("access-secret"), []byte("synthetic-access"), 1)
	auth = bytes.Replace(auth, []byte("refresh-secret"), []byte("synthetic-refresh"), 1)
	return bytes.Replace(auth, []byte("2026-08-29T12:34:56Z"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 1)
}

// SeedTestIdentityForComposition prepares a verified test identity in the
// disposable Keychain for installed-candidate status and sandbox checks.
func SeedTestIdentityForComposition(t *testing.T, value string) {
	t.Helper()
	name, err := ParseCredentialRef(value)
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{provider: newKeychainProvider()}
	auth := UseTestIdentityForComposition(t, store)
	metadata, err := store.verifyAuthJSON(context.Background(), name, auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}
}

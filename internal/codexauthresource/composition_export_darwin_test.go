//go:build darwin

package codexauthresource

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	return SignedTestAuthForComposition(t)
}

// SignedTestAuthForComposition uses keys held only by the test process. An
// installed production binary must reject these credentials on import.
func SignedTestAuthForComposition(t *testing.T) []byte {
	t.Helper()
	auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
	auth = bytes.Replace(auth, []byte("access-secret"), []byte("synthetic-access"), 1)
	auth = bytes.Replace(auth, []byte("refresh-secret"), []byte("synthetic-refresh"), 1)
	return bytes.Replace(auth, []byte("2026-08-29T12:34:56Z"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 1)
}

// SeedTestIdentityForComposition prepares a verified test identity in the
// disposable Keychain for installed-candidate status and sandbox checks. The
// installed candidate is explicitly trusted by the item's ACL; trusting only
// the test executable would prompt when the candidate reads the secret.
func SeedTestIdentityForComposition(t *testing.T, value, candidate string) {
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
	payload, err := encodeEnvelope(auth)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(payload)
	comment, err := encodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(candidate) {
		t.Fatal("resolve trusted native test executables")
	}
	run := func(args ...string) []byte {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/security", args...)
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if err != nil {
			// The arguments contain synthetic credentials. Do not log them.
			t.Fatalf("seed installed candidate Keychain fixture: %v", err)
		}
		return output
	}
	keychain := strings.Trim(strings.TrimSpace(string(run("default-keychain", "-d", "user"))), `"`)
	if !filepath.IsAbs(keychain) {
		t.Fatal("isolated default Keychain is unavailable")
	}
	run("add-generic-password", "-s", keychainService, "-a", string(name), "-j", comment,
		"-w", string(payload), "-T", candidate, "-T", executable, keychain)
}

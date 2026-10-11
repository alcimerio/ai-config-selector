//go:build linux

package executor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
)

// signedLinuxChatGPTAuthJSON returns auth whose ID token verifies against a
// per-test key that the real Store is pointed at for the test's duration.
func signedLinuxChatGPTAuthJSON(t *testing.T, userID, workspace string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "linux-test", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codexauthresource.UseIDTokenKeysForTesting(jwks))
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "linux-test"})
	payload, err := json.Marshal(map[string]any{
		"iss": "https://auth.openai.com", "aud": "app_EMoamEEZ73f0CkXaXp7hrann", "exp": int64(4102444800),
		"sub":                         "subject-fallback",
		"https://api.openai.com/auth": map[string]any{"chatgpt_user_id": userID, "chatgpt_account_id": workspace},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	auth, err := json.Marshal(map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature), "access_token": "access-secret",
			"refresh_token": "refresh-secret", "account_id": workspace,
		},
		"last_refresh": "2026-08-29T12:34:56Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

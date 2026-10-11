// Package codexauthtest builds signed synthetic Codex credentials for tests in
// other packages. It is imported only by test files, never by ACS itself.
package codexauthtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
)

// SignedChatGPTAuthJSON returns auth.json bytes whose ID token is signed by a
// fresh key, and points Stores created afterwards at that key. Call restore
// when the test ends.
func SignedChatGPTAuthJSON(userID, workspace, access, refresh, lastRefresh string) (auth []byte, restore func(), err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "codexauthtest", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		return nil, nil, err
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "codexauthtest"})
	if err != nil {
		return nil, nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": "https://auth.openai.com", "aud": "app_EMoamEEZ73f0CkXaXp7hrann", "exp": int64(4102444800),
		"sub":                         "subject-fallback",
		"https://api.openai.com/auth": map[string]any{"chatgpt_user_id": userID, "chatgpt_account_id": workspace},
	})
	if err != nil {
		return nil, nil, err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, nil, err
	}
	auth, err = json.Marshal(map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature), "access_token": access,
			"refresh_token": refresh, "account_id": workspace,
		},
		"last_refresh": lastRefresh,
	})
	if err != nil {
		return nil, nil, err
	}
	return auth, codexauthresource.UseIDTokenKeysForTesting(jwks), nil
}

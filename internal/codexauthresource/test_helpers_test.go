package codexauthresource

import (
	"encoding/json"
	"testing"
)

const testCleanupProofChallenge = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

func testChatGPTAuthJSON(t *testing.T, userID, workspace string) []byte {
	t.Helper()
	claims := map[string]any{
		"sub": "subject-fallback",
		"iss": openAIIssuer, "aud": codexClientID, "exp": int64(4102444800),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_user_id": userID, "chatgpt_account_id": workspace,
		},
	}
	idToken := signTestIDToken(t, testSigningKey(t), "test-key", claims)
	auth, err := json.Marshal(map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"id_token": idToken, "access_token": "access-secret",
			"refresh_token": "refresh-secret", "account_id": workspace,
		},
		"last_refresh": "2026-08-29T12:34:56Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

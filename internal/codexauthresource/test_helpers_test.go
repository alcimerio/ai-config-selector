package codexauthresource

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

const testCleanupProofChallenge = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

func testChatGPTAuthJSON(t *testing.T, userID, workspace string) []byte {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"sub": "subject-fallback",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_user_id": userID, "chatgpt_account_id": workspace,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	idToken := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
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

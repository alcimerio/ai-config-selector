package codexauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseCredentialRefAcceptsOnlyCanonicalNames(t *testing.T) {
	for _, value := range []string{"work", "personal-2", "team.alpha", "a_b"} {
		parsed, err := ParseCredentialRef(value)
		if err != nil || string(parsed) != value {
			t.Errorf("ParseCredentialRef(%q) = (%q, %v)", value, parsed, err)
		}
	}
	for _, value := range []string{"", "Work", "-work", "work account", strings.Repeat("a", 65)} {
		if _, err := ParseCredentialRef(value); !errors.Is(err, ErrInvalidCredentialRef) {
			t.Errorf("ParseCredentialRef(%q) error = %v, want ErrInvalidCredentialRef", value, err)
		}
	}
}

func TestValidateAuthJSONDerivesStableNonSecretIdentityMetadata(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user-123", "workspace-456")
	metadata, err := validateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "work" || metadata.Method != LoginMethodChatGPT || metadata.Workspace != "workspace-456" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if !strings.HasPrefix(metadata.Fingerprint, "sha256:") || len(metadata.Fingerprint) != 71 {
		t.Fatalf("fingerprint = %q", metadata.Fingerprint)
	}
	for _, secret := range []string{"user-123", "access-secret", "refresh-secret", "id-token"} {
		if strings.Contains(metadata.Fingerprint, secret) {
			t.Fatalf("fingerprint leaks %q", secret)
		}
	}
}

func TestValidateAuthJSONRejectsAmbiguousOrUnsupportedSchemas(t *testing.T) {
	valid := string(testChatGPTAuthJSON(t, "user-123", "workspace-456"))
	tests := []struct {
		name string
		auth string
	}{
		{name: "api mode", auth: strings.Replace(valid, `"chatgpt"`, `"apikey"`, 1)},
		{name: "workspace mismatch", auth: strings.Replace(valid, `"workspace-456"`, `"other-workspace"`, 1)},
		{name: "unknown top-level", auth: strings.Replace(valid, `"auth_mode"`, `"future_secret":"value","auth_mode"`, 1)},
		{name: "unknown token", auth: strings.Replace(valid, `"access_token"`, `"future_token":"value","access_token"`, 1)},
		{name: "mixed api key", auth: strings.Replace(valid, `"auth_mode"`, `"OPENAI_API_KEY":"api-secret","auth_mode"`, 1)},
		{name: "duplicate", auth: strings.Replace(valid, `"auth_mode":"chatgpt"`, `"auth_mode":"chatgpt","auth_mode":"chatgpt"`, 1)},
		{name: "missing refresh", auth: strings.Replace(valid, `"refresh_token":"refresh-secret"`, `"refresh_token":""`, 1)},
		{name: "additional value", auth: valid + ` true`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateAuthJSON("work", []byte(test.auth)); !errors.Is(err, ErrUnsupportedAuth) {
				t.Fatalf("error = %v, want ErrUnsupportedAuth", err)
			}
		})
	}
}

func TestCredentialEnvelopeRoundTripDoesNotExposeMetadataAsSecretStorage(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	payload, err := encodeEnvelope(auth)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeEnvelope(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(auth) {
		t.Fatalf("decoded envelope changed auth JSON")
	}
}

func TestCredentialEnvelopeRejectsUnknownDuplicateAndTrailingFields(t *testing.T) {
	for _, payload := range []string{
		`{"version":1,"future":true,"auth":{}}`,
		`{"version":1,"version":1,"auth":{}}`,
		`{"version":1,"auth":{}} true`,
	} {
		if _, err := decodeEnvelope([]byte(payload)); !errors.Is(err, ErrUnsupportedAuth) {
			t.Fatalf("decodeEnvelope(%q) error = %v", payload, err)
		}
	}
}

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

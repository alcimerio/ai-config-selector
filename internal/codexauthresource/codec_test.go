package codexauthresource

import (
	"encoding/base64"
	"testing"
)

func TestValidateAuthJSONReturnsOnlyStableMetadata(t *testing.T) {
	name, err := ParseCredentialRef("work")
	if err != nil {
		t.Fatal(err)
	}
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	auth := []byte(`{"auth_mode":"chatgpt","tokens":{"id_token":"a.` + claims + `.c","access_token":"access","refresh_token":"refresh"}}`)
	metadata, err := ValidateAuthJSON(name, auth)
	if err != nil {
		t.Fatalf("validate auth: %v", err)
	}
	if metadata.Name != name || metadata.Method != LoginMethodChatGPT || metadata.Fingerprint == "" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestValidateAuthJSONRejectsUnknownFields(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	if _, err := ValidateAuthJSON(name, []byte(`{"auth_mode":"chatgpt","unexpected":true}`)); err != ErrUnsupportedAuth {
		t.Fatalf("error = %v, want unsupported auth", err)
	}
}

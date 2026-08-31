package codexauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maximumAuthJSONSize = 128 * 1024

type authEnvelope struct {
	Version int             `json:"version"`
	Auth    json.RawMessage `json:"auth"`
}

type authTokens struct {
	IDToken      string  `json:"id_token"`
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	AccountID    *string `json:"account_id"`
}

type idTokenClaims struct {
	Subject string `json:"sub"`
	Auth    *struct {
		ChatGPTUserID    string `json:"chatgpt_user_id"`
		UserID           string `json:"user_id"`
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	} `json:"https://api.openai.com/auth"`
}

func validateAuthJSON(name CredentialRef, contents []byte) (IdentityMetadata, error) {
	if len(contents) == 0 || len(contents) > maximumAuthJSONSize {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}

	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	var additional any
	if err := decoder.Decode(&additional); !errors.Is(err, io.EOF) {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	allowed := map[string]struct{}{
		"auth_mode": {}, "OPENAI_API_KEY": {}, "tokens": {}, "last_refresh": {},
		"agent_identity": {}, "personal_access_token": {}, "bedrock_api_key": {},
		"bedrock_access_keys": {},
	}
	for field := range fields {
		if _, ok := allowed[field]; !ok {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
	}

	var mode string
	if err := json.Unmarshal(fields["auth_mode"], &mode); err != nil || mode != string(LoginMethodChatGPT) {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	for _, field := range []string{"OPENAI_API_KEY", "agent_identity", "personal_access_token", "bedrock_api_key", "bedrock_access_keys"} {
		if value, exists := fields[field]; exists && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
	}
	if value, exists := fields["last_refresh"]; exists && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		var timestamp string
		if json.Unmarshal(value, &timestamp) != nil {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
	}

	var tokenFields map[string]json.RawMessage
	if err := json.Unmarshal(fields["tokens"], &tokenFields); err != nil || tokenFields == nil {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	for field := range tokenFields {
		switch field {
		case "id_token", "access_token", "refresh_token", "account_id":
		default:
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
	}
	var tokens authTokens
	if err := json.Unmarshal(fields["tokens"], &tokens); err != nil ||
		strings.TrimSpace(tokens.IDToken) == "" || strings.TrimSpace(tokens.AccessToken) == "" ||
		strings.TrimSpace(tokens.RefreshToken) == "" {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}

	claims, err := parseIDToken(tokens.IDToken)
	if err != nil {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	userID := claims.Subject
	workspace := ""
	if claims.Auth != nil {
		if claims.Auth.ChatGPTUserID != "" {
			userID = claims.Auth.ChatGPTUserID
		} else if claims.Auth.UserID != "" {
			userID = claims.Auth.UserID
		}
		workspace = claims.Auth.ChatGPTAccountID
	}
	if tokens.AccountID != nil && *tokens.AccountID != "" {
		if workspace != "" && workspace != *tokens.AccountID {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
		workspace = *tokens.AccountID
	}
	if userID == "" {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}

	digest := sha256.Sum256([]byte(string(LoginMethodChatGPT) + "\x00" + workspace + "\x00" + userID))
	return IdentityMetadata{
		Name:        name,
		Method:      LoginMethodChatGPT,
		Workspace:   workspace,
		Fingerprint: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func parseIDToken(token string) (idTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return idTokenClaims{}, ErrUnsupportedAuth
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, err
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return idTokenClaims{}, err
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, err
	}
	return claims, nil
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("additional JSON value")
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if delimiter == '[' {
		want = ']'
	}
	if closing != want {
		return fmt.Errorf("invalid JSON closing delimiter")
	}
	return nil
}

func encodeEnvelope(auth []byte) ([]byte, error) {
	return json.Marshal(authEnvelope{Version: recordVersion, Auth: append(json.RawMessage(nil), auth...)})
}

func decodeEnvelope(payload []byte) ([]byte, error) {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return nil, ErrUnsupportedAuth
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope authEnvelope
	if err := decoder.Decode(&envelope); err != nil || envelope.Version != recordVersion || len(envelope.Auth) == 0 {
		return nil, ErrUnsupportedAuth
	}
	var additional any
	if err := decoder.Decode(&additional); !errors.Is(err, io.EOF) {
		return nil, ErrUnsupportedAuth
	}
	return append([]byte(nil), envelope.Auth...), nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

package codexauthresource

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	openAIIssuer    = "https://auth.openai.com"
	openAIJWKSURL   = openAIIssuer + "/.well-known/jwks.json"
	codexClientID   = "app_EMoamEEZ73f0CkXaXp7hrann"
	maximumJWKSSize = 64 * 1024
	jwksCacheTTL    = time.Hour
)

// Keys are shared by imports through this Store, but never persisted alongside
// credentials. A missing or expired key must be fetched from the fixed issuer.
type idTokenVerifier struct {
	fetchJWKS func(context.Context) ([]byte, error)
	now       func() time.Time
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expires   time.Time
}

func newIDTokenVerifier(fetch func(context.Context) ([]byte, error)) *idTokenVerifier {
	return &idTokenVerifier{fetchJWKS: fetch, now: time.Now}
}

func (store *Store) verifyAuthJSON(ctx context.Context, name CredentialRef, auth []byte) (IdentityMetadata, error) {
	if store.verifier == nil {
		return IdentityMetadata{}, ErrIdentityUnverified
	}
	metadata, err := validateAuthJSONWith(name, auth, func(token string) (idTokenClaims, error) {
		return store.verifier.verify(ctx, token)
	})
	if err != nil {
		if errors.Is(err, ErrIdentityUnverified) {
			return IdentityMetadata{}, err
		}
		return IdentityMetadata{}, fmt.Errorf("%w: %w", ErrIdentityUnverified, err)
	}
	return metadata, nil
}

func (verifier *idTokenVerifier) verify(ctx context.Context, token string) (idTokenClaims, error) {
	invalid := func(reason string) (idTokenClaims, error) {
		return idTokenClaims{}, fmt.Errorf("%w: %s", ErrIdentityUnverified, reason)
	}
	parts := strings.Split(token, ".")
	if len(token) > maximumAuthJSONSize || len(parts) != 3 {
		return invalid("invalid ID token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || rejectDuplicateJSONKeys(headerJSON) != nil {
		return invalid("invalid ID token header")
	}
	var header struct {
		Algorithm string          `json:"alg"`
		KeyID     string          `json:"kid"`
		Critical  json.RawMessage `json:"crit"`
		Base64    json.RawMessage `json:"b64"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Algorithm != "RS256" || header.KeyID == "" || header.Critical != nil || header.Base64 != nil {
		return invalid("unsupported ID token header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		return invalid("invalid ID token signature")
	}
	key, err := verifier.key(ctx, header.KeyID)
	if err != nil {
		return invalid("OpenAI signing keys unavailable or key unknown")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return invalid("invalid ID token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || rejectDuplicateJSONKeys(payload) != nil {
		return invalid("invalid ID token claims")
	}
	var registered struct {
		Issuer     string          `json:"iss"`
		Audience   json.RawMessage `json:"aud"`
		Expires    int64           `json:"exp"`
		NotBefore  int64           `json:"nbf"`
		Authorized string          `json:"azp"`
	}
	if json.Unmarshal(payload, &registered) != nil || registered.Issuer != openAIIssuer {
		return invalid("invalid ID token issuer or claims")
	}
	var audiences []string
	var audience string
	if json.Unmarshal(registered.Audience, &audience) == nil && audience != "" {
		audiences = []string{audience}
	} else if json.Unmarshal(registered.Audience, &audiences) != nil {
		return invalid("invalid ID token audience")
	}
	found := false
	for _, candidate := range audiences {
		found = found || candidate == codexClientID
	}
	if !found || (len(audiences) > 1 && registered.Authorized != codexClientID) || (registered.Authorized != "" && registered.Authorized != codexClientID) {
		return invalid("invalid ID token audience")
	}
	now := verifier.now().Unix()
	if registered.Expires <= now || registered.NotBefore > now {
		return invalid("ID token expired or not yet valid")
	}
	claims, err := parseIDToken(token)
	if err != nil || claims.Subject == "" {
		return invalid("invalid ID token identity")
	}
	return claims, nil
}

func (verifier *idTokenVerifier) key(ctx context.Context, id string) (*rsa.PublicKey, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key := verifier.keys[id]; key != nil && verifier.now().Before(verifier.expires) {
		return key, nil
	}
	data, err := verifier.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(data)
	if err != nil {
		return nil, err
	}
	verifier.keys, verifier.expires = keys, verifier.now().Add(jwksCacheTTL)
	if key := keys[id]; key != nil {
		return key, nil
	}
	return nil, ErrIdentityUnverified
}

func parseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	if len(data) > maximumJWKSSize || rejectDuplicateJSONKeys(data) != nil {
		return nil, ErrIdentityUnverified
	}
	var set struct {
		Keys []struct {
			KeyID     string   `json:"kid"`
			Type      string   `json:"kty"`
			Algorithm string   `json:"alg"`
			Use       string   `json:"use"`
			KeyOps    []string `json:"key_ops"`
			Modulus   string   `json:"n"`
			Exponent  string   `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(data, &set) != nil {
		return nil, ErrIdentityUnverified
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range set.Keys {
		if jwk.Type != "RSA" || jwk.KeyID == "" || (jwk.Algorithm != "" && jwk.Algorithm != "RS256") || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		if jwk.KeyOps != nil && (len(jwk.KeyOps) != 1 || jwk.KeyOps[0] != "verify") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
		if err != nil {
			return nil, ErrIdentityUnverified
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, ErrIdentityUnverified
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Int64()
		if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 || keys[jwk.KeyID] != nil {
			return nil, ErrIdentityUnverified
		}
		keys[jwk.KeyID] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if len(keys) == 0 {
		return nil, ErrIdentityUnverified
	}
	return keys, nil
}

func fetchOpenAIJWKS(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, openAIJWKSURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrIdentityUnverified
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumJWKSSize+1))
	if err != nil || len(data) > maximumJWKSSize {
		return nil, ErrIdentityUnverified
	}
	return data, nil
}

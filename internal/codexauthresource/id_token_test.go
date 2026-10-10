package codexauthresource

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := signingKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, id string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": id})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testJWKS(t *testing.T, key *rsa.PublicKey, id string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": id, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestIDTokenVerifier(t *testing.T) *idTokenVerifier {
	t.Helper()
	keys := testJWKS(t, &testSigningKey(t).PublicKey, "test-key")
	return newIDTokenVerifier(func(context.Context) ([]byte, error) { return keys, nil })
}

func testIdentityClaims() map[string]any {
	return map[string]any{
		"iss": openAIIssuer, "aud": codexClientID, "exp": int64(4102444800), "sub": "subject-fallback",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_user_id": "user", "chatgpt_account_id": "workspace",
		},
	}
}

func testAuthWithToken(t *testing.T, token, account string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"auth_mode": "chatgpt", "tokens": authTokens{
			IDToken: token, AccessToken: "new-access", RefreshToken: "new-refresh", AccountID: &account,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCredentialImportsRequireVerifiedIdentity(t *testing.T) {
	key := testSigningKey(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(claims map[string]any) string { return signTestIDToken(t, key, "test-key", claims) }
	valid := sign(testIdentityClaims())
	wrongIssuer := testIdentityClaims()
	wrongIssuer["iss"] = "https://example.invalid"
	expired := testIdentityClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	wrongAudience := testIdentityClaims()
	wrongAudience["aud"] = "other-client"
	notYetValid := testIdentityClaims()
	notYetValid["nbf"] = int64(4102444700)
	missingExpiry := testIdentityClaims()
	delete(missingExpiry, "exp")
	missingAccount := testIdentityClaims()
	delete(missingAccount["https://api.openai.com/auth"].(map[string]any), "chatgpt_account_id")
	tamperedParts := strings.Split(valid, ".")
	payload, err := base64.RawURLEncoding.DecodeString(tamperedParts[1])
	if err != nil {
		t.Fatal(err)
	}
	tamperedParts[1] = base64.RawURLEncoding.EncodeToString(bytes.ReplaceAll(payload, []byte("workspace"), []byte("other-account")))

	cases := []struct {
		name    string
		token   string
		account string
		valid   bool
		offline bool
	}{
		{name: "valid", token: valid, account: "workspace", valid: true},
		{name: "forged signature", token: signTestIDToken(t, otherKey, "test-key", testIdentityClaims()), account: "workspace"},
		{name: "wrong issuer", token: sign(wrongIssuer), account: "workspace"},
		{name: "expired", token: sign(expired), account: "workspace"},
		{name: "wrong audience", token: sign(wrongAudience), account: "workspace"},
		{name: "not yet valid", token: sign(notYetValid), account: "workspace"},
		{name: "missing expiry", token: sign(missingExpiry), account: "workspace"},
		{name: "tampered account claim", token: strings.Join(tamperedParts, "."), account: "other-account"},
		{name: "tampered account field", token: valid, account: "other-account"},
		{name: "cleared account field", token: valid, account: ""},
		{name: "unsigned account fallback", token: sign(missingAccount), account: "workspace"},
		{name: "unsigned token", token: "e30." + tamperedParts[1] + ".c", account: "workspace"},
		{name: "JWKS unavailable", token: valid, account: "workspace", offline: true},
	}
	for _, operation := range []string{"login", "status", "recovery"} {
		t.Run(operation, func(t *testing.T) {
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					original := testChatGPTAuthJSON(t, "user", "workspace")
					metadata, err := ValidateAuthJSON("work", original)
					if err != nil {
						t.Fatal(err)
					}
					projected := testAuthWithToken(t, test.token, test.account)
					created := newProtectedTestSession(t)
					directory := filepath.Join(created.HomeDirectory(), ".codex")
					if err := os.Mkdir(directory, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, "auth.json"), projected, 0o600); err != nil {
						t.Fatal(err)
					}
					marker := quarantineMarker{Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()), Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge, RefreshAllowed: true}
					provider := &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: original}}
					store := &Store{provider: provider, markers: &testMarkers{exists: true, marker: marker}, verifier: newTestIDTokenVerifier(t)}
					if test.offline {
						store.verifier.fetchJWKS = func(context.Context) ([]byte, error) { return nil, errors.New("offline") }
					}
					binding := &Binding{store: store, name: "work", lock: &testLock{}, record: provider.record, hasRecord: operation != "login", root: created.RootDirectory(), sessionID: marker.SessionID, challenge: marker.ProofChallenge}
					var disposition BindingDisposition
					switch operation {
					case "login":
						_, err = binding.CommitLogin(context.Background(), created.RootDirectory())
					case "status":
						disposition, err = binding.FinalizeStatus(context.Background(), created.RootDirectory())
					case "recovery":
						recovery := &RecoveryBinding{store: store, name: "work", lock: &testLock{}, marker: marker}
						disposition, err = recovery.FinalizeRecovery(context.Background(), created.RootDirectory())
					}
					if test.valid {
						if err != nil {
							t.Fatal(err)
						}
						if operation == "login" {
							if !bytes.Equal(provider.created.Auth, projected) {
								t.Fatal("verified login was not stored")
							}
						} else if disposition != CommittedSameIdentityRefresh || provider.replaceCalls != 1 || !bytes.Equal(provider.record.Auth, projected) {
							t.Fatalf("verified refresh not committed: %q, replacements=%d", disposition, provider.replaceCalls)
						}
						return
					}
					if !errors.Is(err, ErrIdentityUnverified) {
						t.Fatalf("error = %v, want ErrIdentityUnverified", err)
					}
					if operation != "login" && disposition != DiscardedProjection {
						t.Fatalf("disposition = %q", disposition)
					}
					if provider.replaceCalls != 0 || provider.created.Auth != nil || !bytes.Equal(provider.record.Auth, original) {
						t.Fatal("unverified credentials changed durable storage")
					}
					for _, secret := range []string{test.token, "new-access", "new-refresh"} {
						if strings.Contains(err.Error(), secret) {
							t.Fatal("verification error contains credential data")
						}
					}
				})
			}
		})
	}
}

func TestIDTokenVerifierCachesAndRefreshesKeys(t *testing.T) {
	key := testSigningKey(t)
	current := time.Now()
	id := "first"
	calls := 0
	offline := false
	verifier := newIDTokenVerifier(func(context.Context) ([]byte, error) {
		calls++
		if offline {
			return nil, errors.New("offline")
		}
		return testJWKS(t, &key.PublicKey, id), nil
	})
	verifier.now = func() time.Time { return current }
	first := signTestIDToken(t, key, "first", testIdentityClaims())
	for range 2 {
		if _, err := verifier.verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("cached verification fetched keys %d times", calls)
	}
	id = "rotated"
	rotated := signTestIDToken(t, key, id, testIdentityClaims())
	if _, err := verifier.verify(context.Background(), rotated); err != nil || calls != 2 {
		t.Fatalf("key rotation = %v, fetches=%d", err, calls)
	}
	offline = true
	if _, err := verifier.verify(context.Background(), rotated); err != nil || calls != 2 {
		t.Fatalf("cached offline verification = %v, fetches=%d", err, calls)
	}
	current = current.Add(jwksCacheTTL)
	if _, err := verifier.verify(context.Background(), rotated); !errors.Is(err, ErrIdentityUnverified) || calls != 3 {
		t.Fatalf("expired offline cache = %v, fetches=%d", err, calls)
	}
	offline = false
	if _, err := verifier.verify(context.Background(), rotated); err != nil || calls != 4 {
		t.Fatalf("expired cache refresh = %v, fetches=%d", err, calls)
	}
	if _, err := verifier.verify(context.Background(), first); !errors.Is(err, ErrIdentityUnverified) {
		t.Fatalf("removed key = %v", err)
	}
}

func TestUnchangedExpiredCredentialsDoNotRequireNetworkVerification(t *testing.T) {
	claims := testIdentityClaims()
	claims["exp"] = int64(1)
	auth := testAuthWithToken(t, signTestIDToken(t, testSigningKey(t), "test-key", claims), "workspace")
	metadata, err := ValidateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"status", "recovery"} {
		t.Run(operation, func(t *testing.T) {
			created := newProtectedTestSession(t)
			provider := &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: auth}}
			marker := quarantineMarker{Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()), Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge, RefreshAllowed: true}
			store := &Store{provider: provider, markers: &testMarkers{exists: true, marker: marker}, verifier: newIDTokenVerifier(func(context.Context) ([]byte, error) {
				t.Fatal("unchanged credentials fetched signing keys")
				return nil, nil
			})}
			binding := &Binding{store: store, name: "work", lock: &testLock{}, record: provider.record, hasRecord: true, root: created.RootDirectory(), sessionID: marker.SessionID, challenge: marker.ProofChallenge}
			if err := binding.Project(created.HomeDirectory()); err != nil {
				t.Fatal(err)
			}
			var disposition BindingDisposition
			var err error
			if operation == "status" {
				disposition, err = binding.FinalizeStatus(context.Background(), created.RootDirectory())
			} else {
				recovery := &RecoveryBinding{store: store, name: "work", lock: &testLock{}, marker: marker}
				disposition, err = recovery.FinalizeRecovery(context.Background(), created.RootDirectory())
			}
			if err != nil || disposition != DiscardedProjection || provider.replaceCalls != 0 || !bytes.Equal(provider.record.Auth, auth) {
				t.Fatalf("unchanged finalization = (%q, %v), replacements=%d", disposition, err, provider.replaceCalls)
			}
		})
	}
}

func TestParseJWKSRejectsInvalidSigningKeys(t *testing.T) {
	valid := testJWKS(t, &testSigningKey(t).PublicKey, "test-key")
	var fields map[string][]map[string]any
	if err := json.Unmarshal(valid, &fields); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, field, value string }{
		{"wrong algorithm", "alg", "HS256"},
		{"wrong type", "kty", "oct"},
		{"encryption key", "use", "enc"},
		{"missing key ID", "kid", ""},
		{"invalid modulus", "n", "?"},
		{"small modulus", "n", "AQAB"},
		{"invalid exponent", "e", "Ag"},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := make(map[string]any)
			for field, value := range fields["keys"][0] {
				key[field] = value
			}
			key[test.field] = test.value
			data, err := json.Marshal(map[string]any{"keys": []any{key}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseJWKS(data); !errors.Is(err, ErrIdentityUnverified) {
				t.Fatalf("invalid key error = %v", err)
			}
		})
	}
	duplicate, err := json.Marshal(map[string]any{"keys": []any{fields["keys"][0], fields["keys"][0]}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{duplicate, []byte(`{"keys":[],"keys":[]}`), append(valid, []byte(` {}`)...), bytes.Repeat([]byte(" "), maximumJWKSSize+1)} {
		if _, err := parseJWKS(data); !errors.Is(err, ErrIdentityUnverified) {
			t.Fatalf("invalid JWKS error = %v", err)
		}
	}
}

func TestIDTokenVerifierValidatesAudienceForms(t *testing.T) {
	for _, test := range []struct {
		name string
		aud  any
		azp  string
		ok   bool
	}{
		{"string", codexClientID, "", true},
		{"array", []string{codexClientID}, "", true},
		{"multiple", []string{codexClientID, "other"}, codexClientID, true},
		{"missing authorized party", []string{codexClientID, "other"}, "", false},
		{"wrong authorized party", codexClientID, "other", false},
		{"missing", nil, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := testIdentityClaims()
			claims["aud"], claims["azp"] = test.aud, test.azp
			token := signTestIDToken(t, testSigningKey(t), "test-key", claims)
			_, err := newTestIDTokenVerifier(t).verify(context.Background(), token)
			if (err == nil) != test.ok {
				t.Fatalf("verification error = %v, want valid=%t", err, test.ok)
			}
		})
	}
}

type jwksRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip jwksRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestFetchOpenAIJWKSUsesFixedEndpointAndBoundsResponse(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, test := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"success", http.StatusOK, `{"keys":[]}`, true},
		{"failure", http.StatusServiceUnavailable, "unavailable", false},
		{"redirect", http.StatusFound, "redirect", false},
		{"oversized", http.StatusOK, strings.Repeat("x", maximumJWKSSize+1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			http.DefaultTransport = jwksRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() != openAIJWKSURL || request.Method != http.MethodGet || request.Header.Get("Authorization") != "" {
					t.Fatal("unexpected JWKS request")
				}
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > jwksFetchTimeout {
					t.Fatal("JWKS request has no bounded deadline")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Location": []string{"https://example.invalid"}}, Body: io.NopCloser(strings.NewReader(test.body)), Request: request}, nil
			})
			_, err := fetchOpenAIJWKS(context.Background())
			if (err == nil) != test.ok {
				t.Fatalf("fetch error = %v, want success=%t", err, test.ok)
			}
		})
	}
}

func TestJWKSFetchTimeoutFailsClosed(t *testing.T) {
	token := signTestIDToken(t, testSigningKey(t), "test-key", testIdentityClaims())
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			endpoint, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			original := http.DefaultTransport
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			defer func() { http.DefaultTransport = original }()
			calls := 0
			http.DefaultTransport = jwksRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				// Only this test transport redirects the fixed issuer to loopback.
				request := r.Clone(r.Context())
				request.URL.Scheme, request.URL.Host = endpoint.Scheme, endpoint.Host
				return transport.RoundTrip(request)
			})
			// Exercise the production bound with no caller deadline for a stalled
			// body, and an earlier caller deadline while awaiting headers.
			ctx := context.Background()
			limit := jwksFetchTimeout
			if phase == "headers" {
				var cancel context.CancelFunc
				limit = 100 * time.Millisecond
				ctx, cancel = context.WithTimeout(ctx, limit)
				defer cancel()
			}
			started := time.Now()
			_, err = newIDTokenVerifier(fetchOpenAIJWKS).verify(ctx, token)
			if !errors.Is(err, ErrIdentityUnverified) || calls != 1 {
				t.Fatalf("stalled JWKS: err=%v, requests=%d", err, calls)
			}
			if elapsed := time.Since(started); elapsed > limit+2*time.Second {
				t.Fatalf("stalled JWKS exceeded its bound: %v", elapsed)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatal("JWKS failure disclosed credentials")
			}
		})
	}
}

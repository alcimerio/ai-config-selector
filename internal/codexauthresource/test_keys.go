package codexauthresource

import (
	"context"
	"testing"
)

// jwksFetcher is the key source for Stores created by New. Production always
// uses the fixed OpenAI issuer; only test binaries can replace it.
var jwksFetcher = fetchOpenAIJWKS

// UseIDTokenKeysForTesting makes Stores created afterwards verify ID tokens
// against the supplied JWKS instead of the OpenAI issuer. It panics outside a
// test binary, so it cannot weaken verification in a shipped ACS.
func UseIDTokenKeysForTesting(jwks []byte) (restore func()) {
	if !testing.Testing() {
		panic("codexauthresource: UseIDTokenKeysForTesting called outside a test binary")
	}
	previous := jwksFetcher
	keys := append([]byte(nil), jwks...)
	jwksFetcher = func(context.Context) ([]byte, error) { return keys, nil }
	return func() { jwksFetcher = previous }
}

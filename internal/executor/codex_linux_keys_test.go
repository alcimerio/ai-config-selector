//go:build linux

package executor

import (
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource/codexauthtest"
)

// signedLinuxChatGPTAuthJSON returns auth whose ID token verifies against a
// per-test key that real Stores created afterwards use.
func signedLinuxChatGPTAuthJSON(t *testing.T, userID, workspace string) []byte {
	t.Helper()
	auth, restore, err := codexauthtest.SignedChatGPTAuthJSON(userID, workspace, "access-secret", "refresh-secret", "2026-08-29T12:34:56Z")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	return auth
}

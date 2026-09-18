//go:build darwin

package acceptance_test

import (
	"os"
	"testing"
)

// This explicit gate runs only the supplied installed candidate. General
// acceptance invocations do not silently pick up an installed real target.
func TestPromotedArtifactNativeRealDevinMCP(t *testing.T) {
	enabled := os.Getenv("ACS_RUN_NATIVE_DEVIN_MCP")
	if enabled == "" {
		t.Skip("explicit ACS_RUN_NATIVE_DEVIN_MCP=1 gate required")
	}
	if enabled != "1" {
		t.Fatal("invalid real Devin MCP gate opt-in")
	}
	for _, key := range []string{"ACS_PROMOTED_BINARY", "ACS_PROMOTED_VERSION", "ACS_PROMOTED_SANDBOX_BACKEND", "ACS_TEST_DEVIN_BINARY", "ACS_TEST_DEVIN_ARCHIVE"} {
		if os.Getenv(key) == "" {
			t.Fatalf("enabled real Devin gate requires %s", key)
		}
	}
	assembleNativeDevinProof(t, devinNativeInput, verifyDevinListing)
}

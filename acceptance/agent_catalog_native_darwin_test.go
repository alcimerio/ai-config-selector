//go:build darwin

package acceptance_test

import (
	"os"
	"testing"
)

func TestPromotedArtifactNativeCustomDevinAgentDiscovery(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AGENT_DISCOVERY") == "" {
		t.Skip("explicit agent discovery assessment opt-in required")
	}
	if os.Getenv("ACS_RUN_NATIVE_AGENT_DISCOVERY") != "1" {
		t.Fatal("invalid agent discovery opt-in")
	}
	for _, key := range []string{"ACS_PROMOTED_BINARY", "ACS_PROMOTED_VERSION", "ACS_PROMOTED_SANDBOX_BACKEND", "ACS_TEST_DEVIN_BINARY", "ACS_TEST_DEVIN_ARCHIVE"} {
		if os.Getenv(key) == "" {
			t.Fatalf("enabled discovery requires %s", key)
		}
	}
	for _, tc := range []struct {
		name    string
		present bool
	}{{"selected", true}, {"absent", false}} {
		t.Run(tc.name, func(t *testing.T) {
			assembleNativeDevinProofWithAgent(t, devinNativeInput, verifyDevinListing, &tc.present)
		})
	}
}

package scripts

import (
	"strings"
	"testing"
)

func TestMacOSVerificationBudgetPreservesBoundedGates(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/macos.yml")
	_, verify, found := strings.Cut(workflow, "\n  verify:\n")
	if !found {
		t.Fatal("macOS verification job is unavailable")
	}
	// The serial normal, race, and panic-stress suites retain per-package
	// deadlines. The job also needs headroom for setup and builds.
	for _, required := range []string{
		"timeout-minutes: 25",
		"go test -v -timeout=5m ./...",
		"go test -race -timeout=10m ./...",
		"-count=20 -timeout=2m",
		"scripts/release-candidate.sh v0.5.1",
	} {
		if !strings.Contains(verify, required) {
			t.Errorf("macOS verification must preserve %q", required)
		}
	}
	for _, forbidden := range []string{"continue-on-error:", "|| true"} {
		if strings.Contains(verify, forbidden) {
			t.Errorf("macOS verification suppresses failure with %q", forbidden)
		}
	}
}

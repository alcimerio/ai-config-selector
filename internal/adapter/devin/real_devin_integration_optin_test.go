package devin_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRealDevinIntegrationRequiresExplicitLocalAuthorization(t *testing.T) {
	command := exec.Command("go", "test", "-tags=integration", "-run", "^TestRealDevinPreflightPreservesExactGlobalCatalogAndExistingLogin$", "-v", ".")
	command.Dir = "."
	command.Env = removeEnvironment(os.Environ(), "ACS_REAL_DEVIN_INTEGRATION")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile and exercise opt-in gate: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "real-Devin integration requires explicit local authorization") || !strings.Contains(string(output), "--- SKIP:") {
		t.Fatalf("integration test did not remain safely disabled: %s", output)
	}
}

func removeEnvironment(environment []string, name string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

package scripts

import (
	"strings"
	"testing"
)

func TestDependencyMaintenanceDoesNotHideSecurityFindings(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/vulnerabilities.yml")
	for _, required := range []string{"scripts/check-go-vulnerabilities.sh source", "GOTOOLCHAIN: local"} {
		if !strings.Contains(workflow, required) {
			t.Errorf("vulnerability workflow omits %q", required)
		}
	}
	for _, forbidden := range []string{"continue-on-error:", "|| true"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("vulnerability workflow suppresses failure with %q", forbidden)
		}
	}
	configuration := readRepositoryFile(t, "..", ".github/dependabot.yml")
	exactException := "ignore:\n      - dependency-name: github.com/charmbracelet/x/vt\n        versions: [\"= v0.1.0\"]"
	if !strings.Contains(configuration, exactException) || strings.Count(configuration, "ignore:") != 1 || strings.Count(configuration, "versions:") != 1 {
		t.Fatal("Dependabot exception must cover only the nonexistent exact vt version")
	}
}

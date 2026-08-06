package scripts

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReleaseCandidateRejectsNoncanonicalVersionsBeforeBuilding(t *testing.T) {
	for _, version := range []string{
		"latest",
		"0.2.0",
		"v01.2.3",
		"v1.02.3",
		"v1.2.03",
		"v1.2.3-rc.1",
		"v0.0.0-20260805002849-816e7b63d8fb",
		"v1.2.3+dirty",
	} {
		t.Run(version, func(t *testing.T) {
			command := exec.Command("sh", "release-candidate.sh", version)
			command.Dir = "."
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("noncanonical version was accepted")
			}
			if !strings.Contains(string(output), "release candidate version must be a canonical SemVer tag") {
				t.Fatalf("unexpected rejection message: %q", output)
			}
		})
	}
}

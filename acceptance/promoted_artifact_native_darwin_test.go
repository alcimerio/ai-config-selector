//go:build darwin

package acceptance_test

import (
	"os/exec"
	"testing"
)

func installPromotedArtifactPolicyRejectedDevin(t *testing.T, root string) string {
	t.Helper()
	// Seatbelt receives one parameter definition for every executable ancestor.
	// A near-PATH_MAX executable path makes that native policy unrepresentable.
	return installPromotedArtifactDeepFakeDevin(t, root, 1000)
}

func promotedArtifactMissingBackendCommand(t *testing.T, binary, home, path, workspace string) *exec.Cmd {
	t.Helper()
	// This outer policy leaves ACS otherwise operational but denies metadata
	// access to the required backend. It exercises the supplied candidate's
	// fail-closed backend check without replacing a protected system binary.
	policy := `(version 1)
(allow default)
(deny file-read-metadata (literal "/usr/bin/sandbox-exec"))`
	command := exec.Command("/usr/bin/sandbox-exec", "-p", policy, "--", binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, path, nil)
	return command
}

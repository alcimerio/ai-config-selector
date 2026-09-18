package acceptance_test

import (
	"os/exec"
	"testing"
)

// Keep the executable witness tests in the normal portable acceptance suite;
// this does not enable the Darwin target gate.
func TestDevinSessionStartHookWitnessPackage(t *testing.T) {
	cmd := exec.Command("go", "test", "./testdata/devin-session-start-hook", "-count=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook witness tests failed: %v\n%s", err, output)
	}
}

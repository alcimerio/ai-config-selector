package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevinTargetLockAndNativeProductionGate(t *testing.T) {
	lock, err := os.ReadFile("devin-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3000.10.21|darwin|arm64|c0b97f8197bf3ce895ff14aa19257c511154b49a0a195bba4962acb5e475c68e|https://static.devin.ai/cli/3000.10.21/devin-3000.10.21-aarch64-apple-darwin.tar.gz"} {
		if !strings.Contains(string(lock), want) {
			t.Fatalf("Devin target lock omits %q", want)
		}
	}
	if output, err := exec.Command("sh", "-n", "install-devin-test-target.sh").CombinedOutput(); err != nil {
		t.Fatalf("installer shell syntax: %v %s", err, output)
	}
	for _, workflowName := range []string{"promoted-artifacts.yml", "release.yml"} {
		data, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflowName))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "scripts/install-devin-test-target.sh") || !strings.Contains(string(data), "ACS_TEST_DEVIN_BINARY=$target_root/bin/devin") {
			t.Errorf("%s omits checksum-locked Devin target installation", workflowName)
		}
	}
	gate, err := os.ReadFile("run-native-candidate-gates.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"TestPromotedArtifactNativeInstructionRules",
		"run_acceptance_test ./acceptance -run '^TestPromotedArtifactNativeInstructionRules$'",
		"TestNativeProductionInstructionRulesReceipts",
		"ACS_RUN_NATIVE_INSTRUCTION_RULES=1 ACS_TEST_DEVIN_BINARY=\"$devin_binary\" go test ./internal/executor",
	} {
		if !strings.Contains(string(gate), want) {
			t.Errorf("shared native gate omits %q", want)
		}
	}
}

package acceptance_test

import (
	"os/exec"
	"testing"
)

func TestDevinNativeMCPJournalSerialization(t *testing.T) {
	cmd := exec.Command("go", "test", "./testdata/devin-native-mcp-server", "-count=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native MCP journal fixture tests failed: %v\n%s", err, output)
	}
}

//go:build darwin || linux

package acceptance_test

import (
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
)

func genericSelectedMCPProfileDocument() []byte {
	return []byte(`{"version":3,"name":"generic-selected-mcp","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-write"}},"executables":{"version":1,"selection":{"entries":[{"id":"server","reference":{"kind":"workspace-relative","path":"generic-mcp-server.sh"}}]}},"mcp":{"version":1,"selection":{"servers":[{"id":"fixture","transport":"stdio","executableRef":"server","arguments":[],"inputRefs":[],"environmentRefs":[],"disabledTools":["blocked"]}]}}},"overlays":{"devin":{"version":1},"codex":{"version":1,"authRef":"interactive-coding"}}}`)
}

func TestGenericSelectedMCPProfileFixtureDecodesThroughProductionRegistry(t *testing.T) {
	adapter, err := devin.New(devin.Config{BinaryPath: "/bin/sh", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Categories().Decode(genericSelectedMCPProfileDocument()); err != nil {
		t.Fatalf("production registry rejected generic selected-MCP fixture: %v", err)
	}
}

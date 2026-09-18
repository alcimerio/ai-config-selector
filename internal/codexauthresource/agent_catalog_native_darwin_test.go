//go:build darwin

package codexauthresource_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeInstalledCustomCodexAgentDiscovery(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AGENT_DISCOVERY") == "" {
		t.Skip("explicit agent discovery assessment opt-in required")
	}
	if os.Getenv("ACS_RUN_NATIVE_AGENT_DISCOVERY") != "1" || os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Fatal("agent discovery requires exact opt-in and native auth gate")
	}
	for _, tc := range []struct {
		name    string
		present bool
	}{{"selected", true}, {"absent", false}} {
		t.Run(tc.name, func(t *testing.T) { runNativeInstalledACSLockedCodexFixtureWithAgent(t, &tc.present) })
	}
}

func runNativeCodexMCPAgentCase(t *testing.T, candidate, home, tools, workspace, grantedTarget, identity string, present *bool) {
	t.Helper()

	const argumentValue = "native MCP argument with spaces"
	const secretValue = "native MCP selected secret sentinel"
	const inputValue = "native MCP input sentinel"
	t.Setenv("ACS_NATIVE_MCP_ARGUMENT", argumentValue)
	t.Setenv("ACS_NATIVE_MCP_SECRET", secretValue)
	inputPath := filepath.Join(workspace, "native-mcp-input.txt")
	if err := os.WriteFile(inputPath, []byte(inputValue), 0o600); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(workspace, "native-mcp-server.sh")
	writeNativeMCPServer(t, serverPath)
	writeNativeCodexMCPProfile(t, home, "mcp", identity)
	markerPath := inputPath + ".mcp-effect"
	descendantPath := inputPath + ".mcp-descendant"
	before := installedSessionSnapshot(t, candidate, home, tools, workspace)
	fixture := newNativeResponsesFixture(t, "", home)
	fixture.mcpScenario = &nativeMCPResponsesScenario{
		serverID: "fixture", allowedTool: "allowed", disabledTool: "blocked",
		callArguments: `{"value":"` + argumentValue + `","input":"` + inputValue + `"}`,
	}
	fixture.privateSentinels = []string{secretValue}
	fixture.descendantReady = descendantPath
	fixture.mcpStartupReceipt = inputPath + ".mcp-startup"
	defer fixture.server.Close()
	coordination := nativeCodexPhaseCoordination{requireMCPStartup: true}
	if present != nil {
		coordination.versionReady = filepath.Join(workspace, "agent-version-ready")
		coordination.versionRelease = filepath.Join(workspace, "agent-version-release")
		coordination.interactiveReady = filepath.Join(workspace, "agent-interactive-ready")
		coordination.interactiveRelease = filepath.Join(workspace, "agent-interactive-release")
		fixture.coordination = &coordination
		fixture.agentCatalog = present
	}
	buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", filepath.Join(tools, "codex"), coordination)
	runInstalledCodexPTY(t, candidate, home, tools, workspace, "mcp", fixture, false)
	descendantPID := fixture.assert(t, true)
	if receipt := readNativeMCPStartupReceipt(fixture.mcpStartupReceipt); receipt != "server-entered,initialize-received,initialize-replied,tools-list-received,tools-list-replied" {
		t.Fatalf("synthetic MCP startup receipts=%q, want server entry and complete initialize/tools-list exchange", receipt)
	}
	if contents, err := os.ReadFile(markerPath); err != nil || string(contents) != "mcp-fixture-call-ok|mcp-secret-environment-ok" {
		t.Fatalf("MCP physical server effect=%q err=%v", contents, err)
	}
	assertNativeProcessRemoved(t, descendantPID, "Codex MCP server descendant survived target settlement")
	assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
	assertNewRemovedInstalledSessions(t, candidate, home, tools, workspace, before, "codex")
	if present != nil {
		fixture.mu.Lock()
		checked := fixture.agentCatalogChecked
		fixture.mu.Unlock()
		if !checked {
			t.Fatal("custom-role initial catalog not checked")
		}
	}
}

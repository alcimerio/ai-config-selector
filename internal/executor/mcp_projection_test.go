package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestSelectedMCPProjectionContainsOnlyReferencesAndToolFilters(t *testing.T) {
	home := filepath.Join(t.TempDir(), "selected home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := "/Applications/ACS/acs"
	recipe := launch.MCPRecipe{ID: "local-server", EnvNames: []string{"MCP_TOKEN"}, Disabled: []string{"write_file"}}
	devinPath, err := writeDevinMCPConfig(home, launcher, []launch.MCPRecipe{recipe})
	if err != nil {
		t.Fatal(err)
	}
	devinBytes, err := os.ReadFile(devinPath)
	if err != nil {
		t.Fatal(err)
	}
	var devin struct {
		Servers map[string]struct {
			Type          string   `json:"type"`
			Command       string   `json:"command"`
			Args          []string `json:"args"`
			DisabledTools []string `json:"disabledTools"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(devinBytes, &devin); err != nil {
		t.Fatal(err)
	}
	projected := devin.Servers[recipe.ID]
	if projected.Type != "stdio" || projected.Command != launcher || len(projected.Args) != 3 || projected.Args[0] != "--acs-mcp-launch" || projected.Args[1] != home || projected.Args[2] != recipe.ID || len(projected.DisabledTools) != 1 || projected.DisabledTools[0] != "write_file" {
		t.Fatalf("Devin MCP projection = %+v", projected)
	}
	if strings.Contains(string(devinBytes), "MCP_TOKEN=") || strings.Contains(string(devinBytes), "secret-value") {
		t.Fatal("Devin MCP projection persisted an environment value")
	}

	semantics := authority.CodexSemantics()
	for index := range semantics.Configuration {
		if semantics.Configuration[index].ID == "codex.mcp" {
			semantics.Configuration[index].Mode = "selected-session-stdio"
		}
	}
	codexPath, err := writeCodexExecutionConfigForSemanticsAndMCP(home, "", "/workspace", semantics, []launch.MCPRecipe{recipe}, launcher)
	if err != nil {
		t.Fatal(err)
	}
	codexBytes, err := os.ReadFile(codexPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`[mcp_servers."local-server"]`, `command = "/Applications/ACS/acs"`,
		`args = ["--acs-mcp-launch", ` + strconvQuote(home) + `, "local-server"]`,
		`env_vars = ["MCP_TOKEN"]`, `disabled_tools = ["write_file"]`,
	} {
		if !strings.Contains(string(codexBytes), required) {
			t.Fatalf("Codex MCP config missing %q: %s", required, codexBytes)
		}
	}
	if strings.Contains(string(codexBytes), "MCP_TOKEN=") || strings.Contains(string(codexBytes), "secret-value") {
		t.Fatal("Codex MCP projection persisted an environment value")
	}
}

func strconvQuote(value string) string { return strconv.Quote(value) }

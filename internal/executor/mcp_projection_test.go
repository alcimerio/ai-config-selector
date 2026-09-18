package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestSelectedMCPProjectionContainsOnlyReferencesAndToolFilters(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "selected home")
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

func TestDevinUserConfigIncludesPinnedStartupDefaultsAndImportControls(t *testing.T) {
	home := t.TempDir()
	path, err := writeDevinUserConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	expected := map[string]any{
		"version":    float64(1),
		"shell":      map[string]any{"setup_complete": true},
		"theme_mode": "dark",
		"read_config_from": map[string]any{
			"cursor": false, "windsurf": false, "claude": false, "opencode": false, "zed": false,
		},
	}
	if !reflect.DeepEqual(config, expected) {
		t.Fatalf("startup Devin config = %+v", config)
	}
}

func TestCodexProjectionCanonicalizesSymlinkedHomeWithoutMCP(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	canonicalHome := filepath.Join(root, "canonical-home")
	if err := os.MkdirAll(canonicalHome, 0o700); err != nil {
		t.Fatal(err)
	}
	logicalHome := filepath.Join(root, "logical-home")
	if err := os.Symlink(canonicalHome, logicalHome); err != nil {
		t.Fatal(err)
	}
	path, err := writeCodexExecutionConfigForSemanticsAndMCP(logicalHome, "", filepath.Join(root, "workspace"), authority.CodexSemantics(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canonicalHome, ".codex", "config.toml")
	if path != want {
		t.Fatalf("Codex config path=%q want canonical %q", path, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatal(err)
	}
}

func TestDevinMCPProjectionCanonicalizesAliasedSessionParent(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	physicalParent := filepath.Join(root, "physical-parent")
	if err := os.Mkdir(physicalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(root, "aliased-parent")
	if err := os.Symlink(physicalParent, aliasParent); err != nil {
		t.Fatal(err)
	}
	logicalHome := filepath.Join(aliasParent, "session-home")
	if err := os.Mkdir(logicalHome, 0o700); err != nil {
		t.Fatal(err)
	}
	physicalHome := filepath.Join(physicalParent, "session-home")
	t.Setenv("HOME", physicalHome)
	seeded := []launch.MCPRecipe{{ID: "server", Arguments: []launch.MCPRecipeArgument{}, EnvNames: []string{}, Disabled: []string{}}}
	recipeDirectory, err := launch.WriteMCPRecipes(logicalHome, seeded)
	if err != nil {
		t.Fatalf("write recipe through ordinary parent alias: %v", err)
	}
	recipeBytes, err := os.ReadFile(filepath.Join(recipeDirectory, "recipes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recipes []launch.MCPRecipe
	if err := json.Unmarshal(recipeBytes, &recipes); err != nil || len(recipes) != 1 || recipes[0].SessionHome != os.Getenv("HOME") {
		t.Fatalf("recipe Session HOME=%+v err=%v, want canonical runtime HOME %q", recipes, err, os.Getenv("HOME"))
	}
	path, err := writeDevinMCPConfig(logicalHome, "/Applications/ACS/acs", recipes)
	if err != nil {
		t.Fatalf("write through ordinary parent alias: %v", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Dir(filepath.Dir(filepath.Dir(resolvedPath))) != physicalHome {
		t.Fatalf("projected MCP config resolved outside canonical Session HOME: path=%q resolved=%q err=%v", path, resolvedPath, err)
	}
	var projected map[string]any
	contents, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(contents, &projected) != nil {
		t.Fatalf("read aliased projection: err=%v", err)
	}
	servers := projected["mcpServers"].(map[string]any)
	args := servers["server"].(map[string]any)["args"].([]any)
	if args[1] != os.Getenv("HOME") {
		t.Fatalf("helper Session HOME argument=%v, want canonical runtime HOME %q", args[1], os.Getenv("HOME"))
	}
	semantics := authority.CodexSemantics()
	for index := range semantics.Configuration {
		if semantics.Configuration[index].ID == "codex.mcp" {
			semantics.Configuration[index].Mode = "selected-session-stdio"
		}
	}
	codexConfig, err := writeCodexExecutionConfigForSemanticsAndMCP(logicalHome, "", root, semantics, recipes, "/Applications/ACS/acs")
	if err != nil {
		t.Fatalf("write Codex MCP projection through parent alias: %v", err)
	}
	codexBytes, err := os.ReadFile(codexConfig)
	if err != nil || !strings.Contains(string(codexBytes), `args = ["--acs-mcp-launch", `+strconvQuote(os.Getenv("HOME"))+`, "server"]`) {
		t.Fatalf("Codex projection does not use canonical runtime HOME: err=%v config=%s", err, codexBytes)
	}

	maliciousHome := filepath.Join(root, "malicious-home")
	if err := os.Mkdir(maliciousHome, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(maliciousHome, ".config")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeDevinUserConfig(maliciousHome); err == nil {
		t.Fatal("projection followed a malicious generated config directory symlink")
	}
	maliciousDevinHome := filepath.Join(root, "malicious-devin-home")
	if err := os.MkdirAll(filepath.Join(maliciousDevinHome, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(maliciousDevinHome, ".config", "devin")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeDevinMCPConfig(maliciousDevinHome, "/Applications/ACS/acs", seeded); err == nil {
		t.Fatal("MCP projection followed a malicious generated .config/devin symlink")
	}
}

func strconvQuote(value string) string { return strconv.Quote(value) }

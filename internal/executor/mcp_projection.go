package executor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func prepareMCPRecipes(home string, servers []launch.MCPServerIntent, executables []launch.ExecutableGrant, paths []launch.FilesystemGrant, environment []launch.EnvironmentIntent) ([]launch.MCPRecipe, string, string, error) {
	if len(servers) == 0 {
		return []launch.MCPRecipe{}, "", "", nil
	}
	recipes, err := launch.CompileMCPRecipes(servers, executables, paths, environment)
	if err != nil {
		return nil, "", "", err
	}
	directory, err := launch.WriteMCPRecipes(home, recipes)
	if err != nil {
		return nil, "", "", err
	}
	launcher, err := os.Executable()
	if err == nil {
		launcher, err = filepath.EvalSymlinks(launcher)
	}
	if err != nil || !filepath.IsAbs(launcher) {
		return nil, "", "", errors.New("MCP launcher executable is unavailable")
	}
	return recipes, directory, launcher, nil
}

func mcpSessionProtections(recipeDirectory, selectedConfig string) []launch.SessionProtection {
	protections := []launch.SessionProtection{}
	if recipeDirectory != "" {
		protections = append(protections, launch.SessionProtection{Path: recipeDirectory, Recursive: true})
	}
	if selectedConfig != "" {
		protections = append(protections, launch.SessionProtection{Path: selectedConfig})
	}
	return protections
}

func writeDevinMCPConfig(home, launcher string, recipes []launch.MCPRecipe) (string, error) {
	if !filepath.IsAbs(home) || !filepath.IsAbs(launcher) {
		return "", errors.New("MCP projection inputs are invalid")
	}
	servers := make(map[string]any, len(recipes))
	for _, recipe := range recipes {
		servers[recipe.ID] = map[string]any{
			"type": "stdio", "command": launcher,
			"args":          []string{"--acs-mcp-launch", filepath.Clean(home), recipe.ID},
			"disabledTools": append([]string{}, recipe.Disabled...),
		}
	}
	encoded, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		return "", errors.New("MCP target config could not be encoded")
	}
	path := filepath.Join(home, ".config", "devin", "mcp_config.json")
	if err := mkdirSessionConfigParents(home, filepath.Dir(path)); err != nil {
		return "", err
	}
	if err := writeSessionProjection(path, append(encoded, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

// writeDevinUserConfig disables documented vendor MCP imports in the isolated
// Devin user configuration. The normal project rules and Devin Skills paths
// remain available; the target still reads its selected MCP config below.
func writeDevinUserConfig(home string) (string, error) {
	if !filepath.IsAbs(home) {
		return "", errors.New("Devin user config Session HOME is invalid")
	}
	path := filepath.Join(home, ".config", "devin", "config.json")
	if err := mkdirSessionConfigParents(home, filepath.Dir(path)); err != nil {
		return "", err
	}
	configuration := map[string]any{"read_config_from": map[string]bool{
		"cursor": false, "windsurf": false, "claude": false, "opencode": false, "zed": false,
	}}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return "", errors.New("Devin user config could not be encoded")
	}
	if err := writeSessionProjection(path, append(encoded, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

func mkdirSessionConfigParents(home, directory string) error {
	cleanHome, err := filepath.EvalSymlinks(filepath.Clean(home))
	if err != nil || cleanHome != filepath.Clean(home) {
		return errors.New("MCP Session HOME identity is unavailable")
	}
	relative, err := filepath.Rel(cleanHome, directory)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || len(relative) > 512 {
		return errors.New("MCP config destination is outside Session HOME")
	}
	current := cleanHome
	for _, part := range splitPathComponents(relative) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("MCP config directory could not be created")
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("MCP config directory could not be verified")
		}
	}
	return nil
}

func splitPathComponents(path string) []string {
	components := []string{}
	for path != "." && path != "" {
		part := filepath.Base(path)
		components = append([]string{part}, components...)
		path = filepath.Dir(path)
	}
	return components
}

func writeSessionProjection(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("MCP target config could not be created")
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("MCP target config could not be persisted")
	}
	return nil
}

func codexMCPConfiguration(recipes []launch.MCPRecipe, launcher, home string) string {
	if len(recipes) == 0 {
		return "mcp_servers = {}\n"
	}
	sort.Slice(recipes, func(i, j int) bool { return recipes[i].ID < recipes[j].ID })
	sections := ""
	for _, recipe := range recipes {
		sections += "[mcp_servers." + quoteTOMLString(recipe.ID) + "]\n"
		sections += "command = " + quoteTOMLString(launcher) + "\n"
		sections += "args = [\"--acs-mcp-launch\", " + quoteTOMLString(filepath.Clean(home)) + ", " + quoteTOMLString(recipe.ID) + "]\n"
		sections += "env_vars = " + quoteTOMLArray(recipe.EnvNames) + "\n"
		if len(recipe.Disabled) > 0 {
			sections += "disabled_tools = " + quoteTOMLArray(recipe.Disabled) + "\n"
		}
		sections += "\n"
	}
	return sections
}

func quoteTOMLString(value string) string { return strconv.Quote(value) }

func quoteTOMLArray(values []string) string {
	encoded := "["
	for index, value := range values {
		if index != 0 {
			encoded += ", "
		}
		encoded += quoteTOMLString(value)
	}
	return encoded + "]"
}

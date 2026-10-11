package codexcompat

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// LinuxPair describes qualification inputs, not production admission. Only the
// direct, sibling musl pair is reviewed; package layouts and arm64 are deferred.
type LinuxPair struct {
	Version                    string
	CLIBytes, CompanionBytes   int64
	CLISHA256, CompanionSHA256 string
}

func LinuxAMD64Pairs() []LinuxPair {
	return []LinuxPair{
		{LegacyVersion, 258227840, 57886648,
			"73dc5888888f411c1f0fa7b81d866e721dcc86b527ce8e3b2cf4708661e823ba",
			"48f3a0d48033039cc7caccd209edb0ee350b81f82ca851a7b129e146e4bec6fb"},
		{CurrentVersion, 284361064, 70644624,
			"78a11f06e0a2dda42d13fba1d50dc62e8cbdb2d5f69789722f4d4d99b5cdbe30",
			"a5c727845f8418acfe5a3d0ff05ad892d76545e51834da817cf77d6d83bdeb18"},
	}
}

// LinuxArguments fixes every authority-bearing option for the experimental
// recipe. The caller cannot append overrides, choose endpoints, or enable MCP.
func LinuxArguments(workspace, directory, operation string) []string {
	args := []string{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`}
	if workspace != "" {
		args = append(args, "-c", "forced_chatgpt_workspace_id="+strconv.Quote(workspace))
	}
	args = append(args,
		"-c", `model_provider="openai"`, "-c", `chatgpt_base_url="https://chatgpt.com/backend-api/"`,
		"-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="never"`,
		"-c", "projects."+strconv.Quote(filepath.Clean(directory))+`.trust_level="untrusted"`,
		"-c", "features.plugins=false", "-c", "features.apps=false", "-c", "mcp_servers={}")
	switch operation {
	case "version":
		return append(args, "--version")
	case "login":
		return append(args, "login", "--device-auth")
	case "status":
		return append(args, "login", "status")
	case "mcp":
		return append(args, "mcp", "list", "--json")
	case "interactive":
		return args
	default:
		return nil
	}
}

func ValidLinuxArguments(args []string, directory string, interactive bool) bool {
	workspace := ""
	if len(args) > 5 && args[4] == "-c" && strings.HasPrefix(args[5], "forced_chatgpt_workspace_id=") {
		var err error
		workspace, err = strconv.Unquote(strings.TrimPrefix(args[5], "forced_chatgpt_workspace_id="))
		if err != nil || workspace == "" || len(workspace) > 256 || strings.ContainsRune(workspace, 0) {
			return false
		}
	}
	for _, operation := range []string{"version", "login", "status", "mcp", "interactive"} {
		if interactive != (operation == "interactive") {
			continue
		}
		if slices.Equal(args, LinuxArguments(workspace, directory, operation)) {
			return true
		}
	}
	return false
}

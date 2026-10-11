package codexcompat

import (
	"slices"
	"strings"
	"testing"
)

func TestLinuxCodexFixedArguments(t *testing.T) {
	for _, workspace := range []string{"", "synthetic-workspace", `workspace"quoted`} {
		for _, operation := range []string{"version", "login", "status", "mcp", "interactive"} {
			args := LinuxArguments(workspace, "/work", operation)
			interactive := operation == "interactive"
			if !ValidLinuxArguments(args, "/work", interactive) || ValidLinuxArguments(args, "/other", interactive) || ValidLinuxArguments(args, "/work", !interactive) {
				t.Fatalf("fixed recipe mismatch: %s", operation)
			}
			for _, extra := range [][]string{{"-c", `cli_auth_credentials_store="keyring"`}, {"--dangerously-bypass-approvals-and-sandbox"}, {"exec", "prompt"}} {
				if ValidLinuxArguments(append(slices.Clone(args), extra...), "/work", interactive) {
					t.Fatal("trailing overrides accepted")
				}
			}
			for i := range args {
				changed := slices.Clone(args)
				changed[i] += "changed"
				if strings.HasPrefix(args[i], "forced_chatgpt_workspace_id=") {
					continue // This value is selected identity metadata.
				}
				if ValidLinuxArguments(changed, "/work", interactive) {
					t.Fatal("changed fixed argument accepted")
				}
			}
		}
	}
	if LinuxArguments("", "/work", "unknown") != nil {
		t.Fatal("unknown operation has a recipe")
	}
}

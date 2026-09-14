package commonprofile

import (
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestMCPSemanticDigestIncludesOrderedReferencesAndFilters(t *testing.T) {
	base := MCPSelection{Servers: []MCPServer{{ID: "server", Transport: "stdio", ExecutableRef: "exe", Arguments: []MCPArgument{{Kind: "environment", Ref: "first"}, {Kind: "path", Ref: "input"}}, InputRefs: []string{"input"}, EnvironmentRefs: []string{"first", "token"}, DisabledTools: []string{"write"}}}}
	planFor := func(selection MCPSelection) authority.Plan {
		return authority.New([]authority.Contribution{{ID: "mcp", Value: MCPContribution{selection: selection}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Semantics: authority.CodexSemantics()})
	}
	noMCP := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Semantics: authority.CodexSemantics()})
	emptyMCP := planFor(MCPSelection{Servers: []MCPServer{}})
	if noMCP.AuthorityDigest() != emptyMCP.AuthorityDigest() {
		t.Fatal("empty MCP capability changed no-MCP authority digest")
	}
	if mode, _ := emptyMCP.Requirements().Semantics.ConfigurationMode("codex.mcp"); mode != "disabled" {
		t.Fatalf("empty MCP semantics mode = %q", mode)
	}
	baseline := planFor(base)
	if mode, _ := baseline.Requirements().Semantics.ConfigurationMode("codex.mcp"); mode != "selected-session-stdio" || !baseline.Requirements().Semantics.Supports(authority.RecipeCodex) {
		t.Fatalf("selected MCP semantics mode = %q", mode)
	}
	mutations := map[string]func(*MCPServer){
		"argument reference": func(server *MCPServer) { server.Arguments[0].Ref = "second" },
		"argument order": func(server *MCPServer) {
			server.Arguments[0], server.Arguments[1] = server.Arguments[1], server.Arguments[0]
		},
		"environment references": func(server *MCPServer) { server.EnvironmentRefs = []string{"first", "other"} },
		"disabled tools":         func(server *MCPServer) { server.DisabledTools = []string{"read"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := MCPSelection{Servers: []MCPServer{base.Servers[0]}}
			changed.Servers[0].Arguments = append([]MCPArgument(nil), base.Servers[0].Arguments...)
			changed.Servers[0].InputRefs = append([]string{}, base.Servers[0].InputRefs...)
			changed.Servers[0].EnvironmentRefs = append([]string{}, base.Servers[0].EnvironmentRefs...)
			changed.Servers[0].DisabledTools = append([]string{}, base.Servers[0].DisabledTools...)
			mutate(&changed.Servers[0])
			if planFor(changed).AuthorityDigest() == baseline.AuthorityDigest() {
				t.Fatalf("%s did not change authority digest", name)
			}
		})
	}
	explanation := baseline.Explanation()
	if len(explanation.Requested) == 0 || len(explanation.Effective) == 0 {
		t.Fatalf("MCP intent missing from explanation: %+v", explanation)
	}
	for _, fact := range explanation.Effective {
		if fact.Kind == "mcp-server" {
			t.Fatal("unapplied MCP projection was reported as effective")
		}
	}
	var found bool
	for _, fact := range explanation.Requested {
		if fact.Kind == "mcp-server" {
			found = true
			if len(fact.Value.MCPArguments) != 2 || fact.Value.MCPArguments[0].Reference != "first" || len(fact.Value.MCPEnvironmentReferences) != 2 || len(fact.Value.MCPDisabledTools) != 1 {
				t.Fatalf("MCP requested facts are incomplete: %+v", fact.Value)
			}
		}
	}
	if !found {
		t.Fatal("MCP stored references were omitted from requested facts")
	}
	if factByID := func() authority.Fact {
		for _, fact := range explanation.TargetAdded {
			if fact.ID == "target.mcp-servers" {
				return fact
			}
		}
		return authority.Fact{}
	}(); factByID.Value.Mode != "selected-session-stdio-projection" || len(factByID.Value.Names) != 1 || factByID.Value.Names[0] != "server" {
		t.Fatalf("selected target applicability is missing from explanation: %+v", explanation.TargetAdded)
	}
}

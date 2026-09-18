package extensionassessment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

// mcpAuthorityProfile is assembled through the existing typed codecs. It
// is not an extension schema or a hand-written authority classifier.
func mcpAuthorityProfile(t *testing.T) profile.Profile {
	t.Helper()
	p := devin.NewSkillsProfile("extension-assessment", nil)
	executables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{{
		ID: "hook", Reference: executableintent.Reference{Kind: string(executableintent.ReferenceWorkspaceRelative), Path: "hooks/witness"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := commonprofile.EncodePathSelection(commonprofile.PathSelection{Entries: []commonprofile.PathEntry{{
		ID: "input", Access: pathintent.AccessReadOnly, Type: pathintent.TypeFile,
		Reference: pathintent.Reference{Kind: string(pathintent.ReferenceWorkspaceRelative), Path: "input.json"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := commonprofile.EncodeEnvironmentSelection(commonprofile.EnvironmentSelection{Entries: []commonprofile.EnvironmentEntry{{
		ID: "mode", Destination: "EXTENSION_MODE", Scope: environmentintent.ScopeAttachedProcessTree,
		Source:         environmentintent.Source{Kind: environmentintent.SourceHostEnvironment, Name: "LANG"},
		Classification: environmentintent.ClassificationNonSecret,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := commonprofile.EncodeMCPSelection(commonprofile.MCPSelection{Servers: []commonprofile.MCPServer{{
		ID: "fixture", Transport: "stdio", ExecutableRef: "hook",
		Arguments: []commonprofile.MCPArgument{{Kind: "path", Ref: "input"}},
		InputRefs: []string{"input"}, EnvironmentRefs: []string{"mode"}, DisabledTools: []string{"blocked"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	p.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: commonprofile.ExecutablesCapabilityVersion, Selection: executables}
	p.Common[commonprofile.PathsCapabilityID] = profile.CommonPayload{Version: commonprofile.PathsCapabilityVersion, Selection: paths}
	p.Common[commonprofile.EnvironmentCapabilityID] = profile.CommonPayload{Version: commonprofile.EnvironmentCapabilityVersion, Selection: environment}
	p.Common[commonprofile.MCPCapabilityID] = profile.CommonPayload{Version: commonprofile.MCPCapabilityVersion, Selection: mcp}
	return p
}

func newTestTarget(t *testing.T) *devin.Adapter {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "devin")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target, err := devin.New(devin.Config{BinaryPath: bin, ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestMCPReferencesUseProductionAuthorityComposition(t *testing.T) {
	target := newTestTarget(t)
	plan, err := target.Categories().ResolveSyntaxFor(context.Background(), mcpAuthorityProfile(t), "devin")
	if err != nil {
		t.Fatal(err)
	}
	servers := plan.MCPServerIntents()
	if len(servers) != 1 || servers[0].ExecutableRef != "hook" || len(servers[0].Arguments) != 1 || servers[0].Arguments[0].Ref != "input" {
		t.Fatalf("production composition lost MCP references: %#v", servers)
	}
	if len(servers[0].EnvironmentRefs) != 1 || servers[0].EnvironmentRefs[0] != "mode" || len(servers[0].DisabledTools) != 1 || servers[0].DisabledTools[0] != "blocked" {
		t.Fatalf("production composition lost MCP environment/filter references: %#v", servers[0])
	}
	if len(plan.EnvironmentIntents()) != 1 {
		t.Fatalf("production plan did not retain environment authority: %#v", plan.EnvironmentIntents())
	}
}

func TestMCPReferencesRejectUnboundAuthorityReferences(t *testing.T) {
	p := mcpAuthorityProfile(t)
	mcp := p.Common[commonprofile.MCPCapabilityID]
	mcp.Selection = []byte(`{"servers":[{"id":"fixture","transport":"stdio","executableRef":"missing","arguments":[],"inputRefs":[],"environmentRefs":[]}]}`)
	p.Common[commonprofile.MCPCapabilityID] = mcp
	if _, err := newTestTarget(t).Categories().ResolveSyntaxFor(context.Background(), p, "devin"); err == nil {
		t.Fatal("unbound MCP reference unexpectedly composed")
	} else if !strings.Contains(err.Error(), "MCP executable reference is not selected") {
		t.Fatal(fmt.Errorf("unexpected unbound-reference error: %w", err))
	}
}

package commonprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/mcpintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
)

const (
	MCPCapabilityID      = "mcp"
	MCPCapabilityVersion = 1
)

type MCPArgument = mcpintent.Argument
type MCPServer = mcpintent.Server
type MCPSelection = mcpintent.Selection

type MCPContribution struct{ selection MCPSelection }

func (value MCPContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	if plan == nil {
		return errors.New("MCP plan is unavailable")
	}
	if len(value.selection.Servers) == 0 {
		return nil
	}
	section := launch.PlanSection{Title: "MCP servers", Items: []launch.PlanItem{}}
	for _, server := range value.selection.Servers {
		section.Items = append(section.Items, launch.PlanItem{Label: server.ID, Details: []launch.PlanDetail{
			{Label: "transport", Value: server.Transport},
			{Label: "executable reference", Value: server.ExecutableRef},
			{Label: "argument references", Value: fmt.Sprint(len(server.Arguments))},
			{Label: "input references", Value: strings.Join(server.InputRefs, ", ")},
			{Label: "environment references", Value: strings.Join(server.EnvironmentRefs, ", ")},
			{Label: "disabled tools", Value: strings.Join(server.DisabledTools, ", ")},
		}})
	}
	plan.Sections = append(plan.Sections, section)
	return nil
}
func (MCPContribution) Materialize(string) error                                 { return nil }
func (MCPContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (value MCPContribution) MCPServerIntents() []launch.MCPServerIntent {
	result := make([]launch.MCPServerIntent, 0, len(value.selection.Servers))
	for _, server := range value.selection.Servers {
		intent := launch.MCPServerIntent{ID: server.ID, Transport: server.Transport, ExecutableRef: server.ExecutableRef,
			Arguments: make([]launch.MCPArgumentIntent, 0, len(server.Arguments)), InputRefs: append([]string{}, server.InputRefs...),
			EnvironmentRefs: append([]string{}, server.EnvironmentRefs...), DisabledTools: append([]string{}, server.DisabledTools...)}
		for _, argument := range server.Arguments {
			intent.Arguments = append(intent.Arguments, launch.MCPArgumentIntent{Kind: argument.Kind, Ref: argument.Ref})
		}
		result = append(result, intent)
	}
	return result
}
func (value MCPContribution) SemanticFacts(sourceVersion int, _ string) authority.Facts {
	facts := authority.Facts{Requested: []authority.Fact{}, Effective: []authority.Fact{}}
	for _, server := range value.selection.Servers {
		count := len(server.Arguments)
		argumentReferences := make([]authority.MCPArgumentReference, 0, len(server.Arguments))
		for _, argument := range server.Arguments {
			argumentReferences = append(argumentReferences, authority.MCPArgumentReference{Kind: argument.Kind, Reference: argument.Ref})
		}
		value := authority.FactValue{Mode: server.Transport, LogicalLocation: server.ID, LogicalReference: server.ExecutableRef, Count: &count, Names: append([]string(nil), server.InputRefs...), MCPArguments: argumentReferences, MCPEnvironmentReferences: append([]string(nil), server.EnvironmentRefs...), MCPDisabledTools: append([]string(nil), server.DisabledTools...), MCPPresent: true}
		source := authority.FactSource{Kind: "profile", ID: MCPCapabilityID, Version: MCPCapabilityVersion}
		facts.Requested = append(facts.Requested, authority.Fact{ID: "common.mcp." + server.ID, Kind: "mcp-server", Value: value, Reason: "stored_reference_intent", Source: source})
	}
	return facts
}

// ValidateReferenceCapabilities is called by the category registry after all
// common selections have been resolved. It binds only opaque IDs and
// classifications; secret values and host paths are not read.
func (value MCPContribution) ValidateReferenceCapabilities(executables, paths, environment any) error {
	executableSelection, executableOK := executables.(executableintent.Selection)
	pathSelection, pathOK := paths.(pathintent.Selection)
	environmentSelection, environmentOK := environment.(environmentintent.Selection)
	if !executableOK || !pathOK || !environmentOK {
		return errors.New("MCP requires selected executable, path, and environment capabilities")
	}
	if err := mcpintent.ValidateReferences(value.selection, executableSelection, pathSelection, environmentSelection); err != nil {
		return fmt.Errorf("validate MCP references: %w", err)
	}
	return nil
}

type MCPBinding = category.Binding[MCPSelection, MCPSelection, MCPContribution]

func NewMCPBinding() (MCPBinding, error) {
	return category.Bind(category.Definition[MCPSelection, MCPSelection, MCPContribution]{
		ID: MCPCapabilityID, SchemaVersion: MCPCapabilityVersion,
		Empty: mcpintent.Empty, LegacyEmpty: mcpintent.Empty,
		Encode: mcpintent.Encode, Decode: mcpintent.Decode,
		Resolve: func(_ context.Context, selection MCPSelection) (MCPSelection, error) {
			return mcpintent.Canonical(selection)
		},
		ResolveSyntax: mcpintent.Canonical,
		ValidateReferences: func(selection MCPSelection, selections map[string]any) error {
			executables, executableOK := selections[ExecutablesCapabilityID].(executableintent.Selection)
			paths, pathsOK := selections[PathsCapabilityID].(pathintent.Selection)
			environment, environmentOK := selections[EnvironmentCapabilityID].(environmentintent.Selection)
			if !executableOK || !pathsOK || !environmentOK {
				return errors.New("MCP requires selected executable, path, and environment capabilities")
			}
			return mcpintent.ValidateReferences(selection, executables, paths, environment)
		},
		Contribute: func(selection MCPSelection) (MCPContribution, error) {
			canonical, err := mcpintent.Canonical(selection)
			if err != nil {
				return MCPContribution{}, err
			}
			return MCPContribution{selection: canonical}, nil
		},
		Count: func(selection MCPSelection) int { return len(selection.Servers) },
	})
}

func DecodeMCPSelection(data json.RawMessage) (MCPSelection, error) { return mcpintent.Decode(data) }
func EncodeMCPSelection(selection MCPSelection) (json.RawMessage, error) {
	return mcpintent.Encode(selection)
}

package commonprofile

import (
	"context"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/networkintent"
)

const NetworkCapabilityID = "network"
const NetworkCapabilityVersion = 1
const LinuxLoopbackGap = "Linux ignores common.network.selection.loopbackPorts: loopback denial and port exceptions are not enforced; network behavior is unchanged."

type NetworkSelection = networkintent.Selection
type NetworkContribution struct{ ports []int }
type NetworkBinding = category.Binding[NetworkSelection, NetworkSelection, NetworkContribution]

func NewNetworkBinding() (NetworkBinding, error) {
	return category.Bind(category.Definition[NetworkSelection, NetworkSelection, NetworkContribution]{
		ID: NetworkCapabilityID, SchemaVersion: NetworkCapabilityVersion, Optional: true,
		Empty: networkintent.Empty, Encode: networkintent.Encode, Decode: networkintent.Decode,
		Resolve: func(_ context.Context, selection NetworkSelection) (NetworkSelection, error) {
			return networkintent.Canonical(selection)
		},
		ResolveSyntax: networkintent.Canonical,
		Contribute: func(selection NetworkSelection) (NetworkContribution, error) {
			return NetworkContribution{ports: append([]int(nil), selection.LoopbackPorts...)}, nil
		},
		Count: func(selection NetworkSelection) int { return len(selection.LoopbackPorts) },
	})
}
func (value NetworkContribution) LoopbackPorts() []int                               { return append([]int(nil), value.ports...) }
func (NetworkContribution) Materialize(string) error                                 { return nil }
func (NetworkContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (value NetworkContribution) SemanticFacts(string) authority.Facts {
	if len(value.ports) == 0 {
		return authority.Facts{}
	}
	names := make([]string, len(value.ports))
	for i, port := range value.ports {
		names[i] = strconv.Itoa(port)
	}
	return authority.Facts{Requested: []authority.Fact{{ID: "common.network.loopback", Kind: "network", Value: authority.FactValue{Mode: "loopback-ports", Names: names}, Reason: "stored_intent", Source: authority.FactSource{Kind: "profile", ID: NetworkCapabilityID, Version: NetworkCapabilityVersion}}}}
}
func (value NetworkContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	allowed := "denied"
	if len(value.ports) != 0 {
		ports := make([]string, len(value.ports))
		for i, port := range value.ports {
			ports[i] = strconv.Itoa(port)
		}
		allowed = strings.Join(ports, ", ") + " (all other loopback ports denied)"
	}
	section := launch.PlanSection{Title: "Loopback network (macOS):", Items: []launch.PlanItem{{Label: "allowed ports", Details: []launch.PlanDetail{{Label: "access", Value: allowed}}}}}
	if runtime.GOOS == "linux" {
		section.Items = append(section.Items, launch.PlanItem{Label: LinuxLoopbackGap})
	}
	plan.Sections = append(plan.Sections, section)
	return nil
}

func EncodeNetworkSelection(selection NetworkSelection) (json.RawMessage, error) {
	return networkintent.Encode(selection)
}
func DecodeNetworkSelection(data json.RawMessage) (NetworkSelection, error) {
	return networkintent.Decode(data)
}

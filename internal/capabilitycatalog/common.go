// Package capabilitycatalog owns provider-neutral structural descriptors for
// common Profile capabilities. Selection codecs, defaults, validation and
// runtime behavior remain with the individual capability implementations.
package capabilitycatalog

// CommonCapability describes the structural capability surface shared by
// active registries, passive Profile admission and portable exchange.
type CommonCapability struct {
	ID       string
	Version  int
	Required bool
}

var commonCapabilities = []CommonCapability{
	{ID: "skills", Version: 1, Required: true},
	{ID: "workspace", Version: 1, Required: true},
	{ID: "paths", Version: 1},
	{ID: "exclusions", Version: 1},
	{ID: "executables", Version: 1},
	{ID: "environment", Version: 1},
	{ID: "instructions", Version: 1},
	{ID: "mcp", Version: 1},
}

// CommonCapabilities returns an independent copy in stable catalog order.
func CommonCapabilities() []CommonCapability {
	return append([]CommonCapability(nil), commonCapabilities...)
}

// LookupCommon returns one structural descriptor by its exact, case-sensitive ID.
func LookupCommon(id string) (CommonCapability, bool) {
	for _, capability := range commonCapabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return CommonCapability{}, false
}

// SupportsCommonV3 validates that one active Registry contains the required
// common capabilities and no capability passive admission would reject.
// Payload versions and selections are still validated by each consumer.
func SupportsCommonV3(ids []string) bool {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, supported := LookupCommon(id); !supported || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, capability := range commonCapabilities {
		if capability.Required && !seen[capability.ID] {
			return false
		}
	}
	return true
}

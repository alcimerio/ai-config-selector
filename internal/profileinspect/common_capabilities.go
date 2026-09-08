package profileinspect

// CommonCapability describes the structural capability surface shared by
// active registries and passive Profile admission. Value decoding remains in
// dependency-light intent packages and never resolves a host resource.
type CommonCapability struct {
	ID       string
	Version  int
	Required bool
}

var commonCapabilities = []CommonCapability{
	{ID: "skills", Version: 1, Required: true},
	{ID: "workspace", Version: 1, Required: true},
	{ID: "paths", Version: 1},
	{ID: "executables", Version: 1},
	{ID: "environment", Version: 1},
}

func CommonCapabilities() []CommonCapability {
	return append([]CommonCapability(nil), commonCapabilities...)
}

func commonCapability(id string) (CommonCapability, bool) {
	for _, capability := range commonCapabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return CommonCapability{}, false
}

// SupportsCommonV3 validates that one active Registry contains the required
// common capabilities and no capability passive admission would reject.
func SupportsCommonV3(ids []string) bool {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, supported := commonCapability(id); !supported || seen[id] {
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

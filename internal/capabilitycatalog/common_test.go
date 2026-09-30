package capabilitycatalog

import (
	"reflect"
	"testing"
)

func TestCommonCapabilitiesPreserveStructuralContract(t *testing.T) {
	want := []CommonCapability{
		{ID: "skills", Version: 1, Required: true},
		{ID: "workspace", Version: 1, Required: true},
		{ID: "paths", Version: 1},
		{ID: "executables", Version: 1},
		{ID: "environment", Version: 1},
		{ID: "instructions", Version: 1},
		{ID: "mcp", Version: 1},
	}
	if got := CommonCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("common capabilities = %#v, want %#v", got, want)
	}
	for _, capability := range want {
		if got, ok := LookupCommon(capability.ID); !ok || got != capability {
			t.Errorf("lookup %q = %#v, %v; want %#v, true", capability.ID, got, ok, capability)
		}
	}
	if got, ok := LookupCommon("unknown"); ok || got != (CommonCapability{}) {
		t.Fatalf("unknown lookup = %#v, %v", got, ok)
	}
}

func TestCommonCapabilitiesReturnIndependentCopies(t *testing.T) {
	want := CommonCapabilities()
	copy := CommonCapabilities()
	for i := range copy {
		copy[i] = CommonCapability{ID: "mutated", Version: 99, Required: !copy[i].Required}
	}
	if got := CommonCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller mutation changed catalog: %#v", got)
	}
	for _, capability := range want {
		got, ok := LookupCommon(capability.ID)
		if !ok || got != capability {
			t.Fatalf("caller mutation changed lookup %q: %#v, %v", capability.ID, got, ok)
		}
		got.ID, got.Version, got.Required = "mutated", 99, !got.Required
		if again, ok := LookupCommon(capability.ID); !ok || again != capability {
			t.Fatalf("lookup mutation changed catalog %q: %#v, %v", capability.ID, again, ok)
		}
	}
	if !SupportsCommonV3([]string{"skills", "workspace"}) || SupportsCommonV3([]string{"mutated", "workspace"}) {
		t.Fatal("caller mutation changed common admission")
	}
}

func TestSupportsCommonV3PreservesRequirednessAndExactIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"missing skills", []string{"workspace"}, false},
		{"missing workspace", []string{"skills"}, false},
		{"required only", []string{"skills", "workspace"}, true},
		{"order independent", []string{"workspace", "skills"}, true},
		{"all", []string{"skills", "workspace", "paths", "executables", "environment", "instructions", "mcp"}, true},
		{"unknown", []string{"skills", "workspace", "future"}, false},
		{"duplicate required", []string{"skills", "workspace", "skills"}, false},
		{"duplicate optional", []string{"skills", "workspace", "mcp", "mcp"}, false},
		{"case alias", []string{"Skills", "workspace"}, false},
		{"empty ID", []string{"skills", "workspace", ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsCommonV3(tc.ids); got != tc.want {
				t.Fatalf("SupportsCommonV3(%q) = %v, want %v", tc.ids, got, tc.want)
			}
		})
	}
}

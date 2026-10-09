package profileinspect_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/capabilitycatalog"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestCommonCatalogConsumersAgreeOnEveryCapabilitySubset(t *testing.T) {
	registry, full := catalogProfile(t)
	catalog := capabilitycatalog.CommonCapabilities()
	if len(full.Common) != len(catalog) {
		t.Fatalf("active capabilities = %d, catalog = %d", len(full.Common), len(catalog))
	}
	for _, descriptor := range catalog {
		if payload, ok := full.Common[descriptor.ID]; !ok || payload.Version != descriptor.Version {
			t.Fatalf("active payload for %q = %#v, %v; catalog version = %d", descriptor.ID, payload, ok, descriptor.Version)
		}
	}

	// Exercise every optional-capability combination, including all ways of
	// omitting required capabilities, using the real capability-owned codecs.
	for mask := 0; mask < 1<<len(catalog); mask++ {
		t.Run(fmt.Sprintf("subset-%02x", mask), func(t *testing.T) {
			candidate := full
			candidate.Common = map[string]profile.CommonPayload{}
			ids := []string{}
			want := true
			for i, descriptor := range catalog {
				if mask&(1<<i) != 0 {
					candidate.Common[descriptor.ID] = full.Common[descriptor.ID]
					ids = append(ids, descriptor.ID)
				} else if descriptor.Required {
					want = false
				}
			}
			if got := capabilitycatalog.SupportsCommonCatalog(ids); got != want {
				t.Fatalf("catalog admission = %v, want %v", got, want)
			}
			assertCatalogAdmission(t, registry, candidate, want, "invalid_structure", "unsupported common capability")

			var registrations []category.Registration
			for _, registration := range registry.Registrations() {
				if _, present := candidate.Common[registration.ID()]; present {
					registrations = append(registrations, registration)
				}
			}
			subset, err := category.NewRegistry("devin", registrations...)
			if err != nil {
				t.Fatal(err)
			}
			created, err := subset.NewProfile("example", subset.NewDraft())
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(created)
			if err != nil {
				t.Fatal(err)
			}
			if got := profileinspect.InspectBytes("example", encoded).Status == "valid"; got != want {
				t.Fatalf("subset registry Profile passive admission = %v, want %v", got, want)
			}
		})
	}
}

func TestCommonCatalogConsumersPreserveUnknownAndVersionErrors(t *testing.T) {
	registry, full := catalogProfile(t)
	for _, id := range []string{"future", "Skills", ""} {
		t.Run("unknown-"+id, func(t *testing.T) {
			candidate := cloneCatalogProfile(full)
			candidate.Common[id] = profile.CommonPayload{Version: 1, Selection: json.RawMessage(`[]`)}
			assertCatalogAdmission(t, registry, candidate, false, "unsupported_content", "unsupported common capability")
		})
	}
	for _, descriptor := range capabilitycatalog.CommonCapabilities() {
		t.Run("version-"+descriptor.ID, func(t *testing.T) {
			candidate := cloneCatalogProfile(full)
			payload := candidate.Common[descriptor.ID]
			payload.Version = descriptor.Version + 1
			candidate.Common[descriptor.ID] = payload
			message := "unsupported " + descriptor.ID + " capability"
			if descriptor.ID == "mcp" {
				message = "unsupported MCP capability"
			}
			if descriptor.Required {
				message = "unsupported common capability"
			}
			assertCatalogAdmission(t, registry, candidate, false, "unsupported_content", message)
		})
	}
}

func catalogProfile(t *testing.T) (*category.Registry, profile.Profile) {
	t.Helper()
	adapter, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry := adapter.Categories()
	candidate, err := registry.NewProfile("example", registry.NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	return registry, candidate
}

func cloneCatalogProfile(candidate profile.Profile) profile.Profile {
	common := make(map[string]profile.CommonPayload, len(candidate.Common))
	for id, payload := range candidate.Common {
		common[id] = payload
	}
	candidate.Common = common
	return candidate
}

func assertCatalogAdmission(t *testing.T, registry *category.Registry, candidate profile.Profile, want bool, diagnosticCode, exportError string) {
	t.Helper()
	// Keep an empty common object present to test requiredness rather than the
	// Profile struct's omitempty serialization behavior.
	data, err := json.Marshal(map[string]any{
		"version": candidate.Version, "name": candidate.Name,
		"common": candidate.Common, "overlays": candidate.Overlays,
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := profileinspect.InspectBytes(candidate.Name, data)
	if got := entry.Status == "valid"; got != want {
		t.Fatalf("passive admission = %#v, want valid = %v", entry, want)
	}
	if !want && (entry.Diagnostic == nil || entry.Diagnostic.Code != diagnosticCode) {
		t.Fatalf("passive diagnostic = %#v, want %s", entry.Diagnostic, diagnosticCode)
	}
	if _, err := registry.DecodeNamed(candidate.Name, data); (err == nil) != want {
		t.Fatalf("active admission error = %v, want valid = %v", err, want)
	} else if !want && err.Error() != entry.Diagnostic.Message {
		t.Fatalf("active admission error = %q, want passive diagnostic %q", err.Error(), entry.Diagnostic.Message)
	}
	encoded, _, err := profileexchange.Export(candidate)
	if (err == nil) != want {
		t.Fatalf("exchange export error = %v, want valid = %v", err, want)
	}
	if !want {
		if err.Error() != exportError {
			t.Fatalf("exchange error = %q, want %q", err.Error(), exportError)
		}
		return
	}
	result := profileexchange.Decode(encoded, nil, candidate.Name)
	if result.Code != profileexchange.CodeValid || result.Candidate == nil {
		t.Fatalf("exchange round trip = %#v", result)
	}
}

package profileinspect

import "testing"

func TestVersionThreeInspectsIndependentCapabilitiesAndInactiveOverlays(t *testing.T) {
	data := []byte(`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":7,"future":{"opaque":true}},"devin":{"version":1}}}`)
	entry := InspectBytes("example", data)
	if entry.Status != "valid" || entry.Workspace == nil || *entry.Workspace != "read-only" {
		t.Fatalf("entry = %#v", entry)
	}
	if len(entry.Overlays) != 2 || entry.Overlays[0].ID != "codex" || entry.Overlays[0].Support != "inactive-unknown" || entry.Overlays[1].Support != "supported" {
		t.Fatalf("overlays = %#v", entry.Overlays)
	}
}

func TestVersionThreeRejectsUnsupportedCommonAndSelectedOverlayExtensions(t *testing.T) {
	for _, data := range []string{
		`{"version":3,"name":"example","common":{"skills":{"version":2,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`,
		`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1,"future":true}}}`,
	} {
		entry := InspectBytes("example", []byte(data))
		if entry.Status == "valid" && (len(entry.Overlays) == 0 || entry.Overlays[0].Support == "supported") {
			t.Fatalf("accepted unsupported content: %#v", entry)
		}
	}
}

func TestVersionThreeInspectsSupportedCodexOverlayWithoutDisclosingAuthRef(t *testing.T) {
	data := []byte(`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"work"},"devin":{"version":1}}}`)
	entry := InspectBytes("example", data)
	if entry.Status != "valid" || len(entry.Overlays) != 2 {
		t.Fatalf("entry = %#v", entry)
	}
	if entry.Overlays[0].ID != "codex" || entry.Overlays[0].Support != "supported" {
		t.Fatalf("Codex overlay = %#v", entry.Overlays[0])
	}
	for _, overlay := range entry.Overlays {
		if overlay.ID == "work" {
			t.Fatalf("opaque authRef escaped as overlay metadata: %#v", entry.Overlays)
		}
	}
}

func TestVersionThreeRejectsInvalidCodexOverlayContract(t *testing.T) {
	for _, data := range []string{
		`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1}}}`,
		`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"UPPER"}}}`,
		`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"work","arguments":["--unsafe"]}}}`,
	} {
		entry := InspectBytes("example", []byte(data))
		if entry.Status == "valid" && len(entry.Overlays) == 1 && entry.Overlays[0].Support == "supported" {
			t.Fatalf("accepted invalid Codex overlay: %#v", entry)
		}
	}
}

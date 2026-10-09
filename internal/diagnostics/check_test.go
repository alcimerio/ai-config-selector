package diagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLaunchCheckSelectsOverlayAndLegacyBinding(t *testing.T) {
	for _, tc := range []struct{ body, target, status, code string }{
		{`{"version":1,"name":"example","target":"devin","skillReferences":[]}`, "devin", "pass", "legacy_devin_binding"},
		{`{"version":1,"name":"example","target":"devin","skillReferences":[]}`, "sandbox", "pass", "legacy_common_only"},
		{`{"version":2,"name":"example","target":"devin","categories":{}}`, "codex", "fail", "legacy_target_mismatch"},
		{`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"private-unknown":{"version":99,"selection":{"private":"secret"}}}}`, "sandbox", "pass", "common_only"},
		{`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{}}`, "sandbox", "pass", "common_only"},
		{`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{}}`, "codex", "fail", "selected_overlay_missing"},
		{`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":99,"selection":{}}}}`, "codex", "fail", "selected_overlay_unsupported"},
		{`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"private-identity"}}}`, "codex", "pass", "selected_overlay_supported"},
	} {
		home := t.TempDir()
		writeProfile(t, home, tc.body)
		got := LaunchCheck(context.Background(), "example", tc.target, func() (string, error) { return home, nil })
		check(t, got, "profile.overlays", tc.status, tc.code)
		data, _ := json.Marshal(got)
		if len(data) > 8192 || strings.Contains(string(data), "secret") || strings.Contains(string(data), home) || strings.Contains(string(data), "private-unknown") {
			t.Fatalf("unsanitized/unbounded %s", data)
		}
		check(t, got, "runtime.enforcement", "unchecked", "")
		check(t, got, "native.readiness", "unchecked", "not_requested")
		check(t, got, "operation.completion", "pass", "completed")
		check(t, got, "authentication", "unchecked", "")
		check(t, got, "executable.version", "unchecked", "")
	}
}

func TestLaunchCheckReportsExclusionsWithoutOpeningOrDisclosingBindings(t *testing.T) {
	home := t.TempDir()
	writeProfile(t, home, `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"private","type":"file","reference":{"kind":"local-absolute","path":"/unavailable/private"}}]}}},"overlays":{}}`)
	got := LaunchCheck(context.Background(), "example", "sandbox", func() (string, error) { return home, nil })
	check(t, got, "profile.structure", "pass", "")
	check(t, got, "profile.exclusions", "unchecked", "launch_required")
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), "Configured exclusions: 1.") || strings.Contains(string(raw), "/unavailable/private") || strings.Contains(string(raw), home) {
		t.Fatalf("check=%s", raw)
	}
}

package profile

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestProfileEncodingPreservesExistingEnvelopeBytes(t *testing.T) {
	// This alias represents the encoder before Profile gained MarshalJSON.
	type previousEncoding Profile
	for _, candidate := range []Profile{
		{Version: 1, Name: "shared", Common: map[string]CommonPayload{"workspace": {Version: 1, Selection: json.RawMessage(`{"access":"read-only"}`)}}, Overlays: map[string]OverlayPayload{"codex": {Version: 1, AuthRef: "work"}, "devin": {Version: 1}}},
		{Version: 1, Name: "missing-overlay", Common: map[string]CommonPayload{"workspace": {Version: 1, Selection: json.RawMessage(`{"access":"read-only"}`)}}},
	} {
		before, err := json.MarshalIndent(previousEncoding(candidate), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.MarshalIndent(candidate, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("%s changed canonical bytes:\nbefore %s\nafter %s", candidate.Name, before, after)
		}
	}
}
func TestProfileEncodingKeepsExplicitEmptyOverlays(t *testing.T) {
	candidate := Profile{Version: 1, Name: "common-only", Overlays: map[string]OverlayPayload{}}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if string(document["overlays"]) != "{}" {
		t.Fatalf("explicit empty overlays were omitted: %s", encoded)
	}
}

func TestSupportedVersionAcceptsCurrentAndReadAliasOnly(t *testing.T) {
	for version, want := range map[int]bool{0: false, 1: true, 2: false, 3: true, 4: false} {
		if got := SupportedVersion(version); got != want {
			t.Errorf("SupportedVersion(%d) = %v, want %v", version, got, want)
		}
	}
	if CurrentVersion != 1 {
		t.Fatalf("CurrentVersion = %d, want 1", CurrentVersion)
	}
}

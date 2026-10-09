package profileexchange

import (
	"bytes"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"testing"
)

func TestExclusionsPortableRoundTripAndBindingAdmission(t *testing.T) {
	candidate := fixtureProfile(t)
	selection := commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{
		{ID: "repo", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: "workspace-relative", Path: ".agents/skills"}},
		{ID: "local", Type: "file", Reference: commonprofile.ExclusionReference{Kind: "local-absolute", Path: "/Users/private/hidden.txt"}},
	}}
	encoded, err := commonprofile.EncodeExclusionSelection(selection)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.ExclusionsCapabilityID] = profile.CommonPayload{Version: 1, Selection: encoded}
	document, report, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if report.PathBindings != 1 || bytes.Contains(document, []byte("/Users/private")) {
		t.Fatalf("private binding export: %s", document)
	}
	if missing := Decode(document, nil, "imported"); missing.Candidate != nil || missing.Bindings == "complete" {
		t.Fatalf("missing bindings accepted: %#v", missing)
	}
	bindings := []byte(`{"bindingVersion":3,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{"path-1":"/Users/other/hidden.txt"},"executables":{},"environment":{}}`)
	result := Decode(document, bindings, "imported")
	if result.Code != CodeValid || result.Candidate == nil {
		t.Fatalf("decode=%#v\n%s", result, document)
	}
	got, err := commonprofile.DecodeExclusionSelection(result.Candidate.Common["exclusions"].Selection)
	if err != nil || len(got.Entries) != 2 || got.Entries[0].Reference.Path != "/Users/other/hidden.txt" || got.Entries[1].Reference.Path != ".agents/skills" {
		t.Fatalf("round trip=%#v %v", got, err)
	}
	for _, mutation := range [][]byte{
		bytes.Replace(document, []byte(`"exclusions":`), []byte(`"Exclusions":`), 1),
		bytes.Replace(document, []byte(`"type": "file"`), []byte(`"type": "file", "access":"read-only"`), 1),
		bytes.Replace(document, []byte(`"exchangeVersion": 3`), []byte(`"exchangeVersion": 2`), 1),
	} {
		if got := Decode(mutation, bindings, "invalid"); got.Candidate != nil || got.Code == CodeValid {
			t.Fatalf("invalid exchange accepted: %#v", got)
		}
	}
}

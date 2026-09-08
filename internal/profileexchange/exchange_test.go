package profileexchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestExportIsDeterministicAndRemovesLocalBindings(t *testing.T) {
	candidate := fixtureProfile(t)
	first, report, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("exports differ:\n%s\n%s", first, second)
	}
	reordered := candidate
	reordered.Common = map[string]profile.CommonPayload{"workspace": candidate.Common["workspace"], "skills": candidate.Common["skills"]}
	reordered.Overlays = map[string]profile.OverlayPayload{"codex": candidate.Overlays["codex"], "devin": candidate.Overlays["devin"]}
	third, _, err := Export(reordered)
	if err != nil || !bytes.Equal(first, third) {
		t.Fatalf("map insertion order changed export: %v\n%s\n%s", err, first, third)
	}
	for _, sentinel := range []string{"shared-agents", "devin-config", `"work"`, "/private"} {
		if bytes.Contains(first, []byte(sentinel)) {
			t.Fatalf("export contains local value %q: %s", sentinel, first)
		}
	}
	if report.SourceBindings != 2 || report.AuthenticationBindings != 1 {
		t.Fatalf("report = %#v", report)
	}
	if first[len(first)-1] != '\n' {
		t.Fatal("export has no final newline")
	}
	golden, err := os.ReadFile("testdata/complete.golden.json")
	if err != nil || !bytes.Equal(first, golden) {
		t.Fatalf("golden mismatch: %v\nwant:\n%s\ngot:\n%s", err, golden, first)
	}
}

func TestDecodeRequiresBindingsAndPreservesIntent(t *testing.T) {
	exported, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	result := Decode(exported, nil, "imported")
	if result.Code != CodeBindingRequired || result.Candidate != nil {
		t.Fatalf("unbound result = %#v", result)
	}
	bindings := []byte(`{"bindingVersion":1,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"}}`)
	result = Decode(exported, bindings, "imported")
	if result.Code != CodeValid || result.Candidate == nil {
		t.Fatalf("bound result = %#v", result)
	}
	if result.Candidate.Name != "imported" || result.Candidate.Overlays["codex"].AuthRef != "personal" {
		t.Fatalf("candidate = %#v", result.Candidate)
	}
}

func TestDecodeRejectsPostBindingAliasCollision(t *testing.T) {
	document := []byte(`{"exchangeVersion":1,"profile":{"common":{"skills":{"version":1,"selection":[{"sourceBinding":"source-1","relativePath":"Review"},{"sourceBinding":"source-2","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}},"requirements":{"sources":[{"id":"source-1"},{"id":"source-2"}],"authentications":[]}}`)
	bindings := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents","source-2":"shared-agents"},"authentications":{}}`)
	result := Decode(document, bindings, "imported")
	if result.Code != CodeBindingConflict || result.Candidate != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestDecodeRejectsUnicodeCaseFoldAliasesSymbolicallyAndAfterBinding(t *testing.T) {
	symbolic := []byte(`{"exchangeVersion":1,"profile":{"common":{"skills":{"version":1,"selection":[{"sourceBinding":"source-1","relativePath":"Review/Σ"},{"sourceBinding":"source-1","relativePath":"review/ς"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}},"requirements":{"sources":[{"id":"source-1"}],"authentications":[]}}`)
	if result := Decode(symbolic, nil, "imported"); result.Code != CodeUnsafePath || result.Candidate != nil {
		t.Fatalf("symbolic aliases = %#v", result)
	}

	postBinding := []byte(`{"exchangeVersion":1,"profile":{"common":{"skills":{"version":1,"selection":[{"sourceBinding":"source-1","relativePath":"Review/Σ"},{"sourceBinding":"source-2","relativePath":"review/ς"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}},"requirements":{"sources":[{"id":"source-1"},{"id":"source-2"}],"authentications":[]}}`)
	same := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents","source-2":"shared-agents"},"authentications":{}}`)
	if result := Decode(postBinding, same, "imported"); result.Code != CodeBindingConflict || result.Candidate != nil {
		t.Fatalf("post-binding aliases = %#v", result)
	}
	distinct := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents","source-2":"devin-config"},"authentications":{}}`)
	if result := Decode(postBinding, distinct, "imported"); result.Code != CodeValid || result.Candidate == nil {
		t.Fatalf("cross-source aliases = %#v", result)
	}
}

func TestDecodeChecksPostBindingOverlapAndPreservesCrossSourceNamespace(t *testing.T) {
	document := []byte(`{"exchangeVersion":1,"profile":{"common":{"skills":{"version":1,"selection":[{"sourceBinding":"source-1","relativePath":"review"},{"sourceBinding":"source-2","relativePath":"review/child"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}},"requirements":{"sources":[{"id":"source-1"},{"id":"source-2"}],"authentications":[]}}`)
	same := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents","source-2":"shared-agents"},"authentications":{}}`)
	if result := Decode(document, same, "imported"); result.Code != CodeBindingConflict || result.Candidate != nil {
		t.Fatalf("same-source overlap = %#v", result)
	}
	distinct := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents","source-2":"devin-config"},"authentications":{}}`)
	if result := Decode(document, distinct, "imported"); result.Code != CodeValid || result.Candidate == nil {
		t.Fatalf("cross-source namespace = %#v", result)
	}
}

func TestDecodeDistinguishesMissingFromInvalidEmptyBindingFile(t *testing.T) {
	exported, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	if result := Decode(exported, nil, "imported"); result.Code != CodeBindingRequired || result.Bindings != "unresolved" {
		t.Fatalf("missing = %#v", result)
	}
	if result := Decode(exported, []byte{}, "imported"); result.Code != CodeInvalidJSON || result.Bindings != "fail" {
		t.Fatalf("empty = %#v", result)
	}
}

func TestDecodeRejectsHostileStructures(t *testing.T) {
	valid, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate":         bytes.Replace(valid, []byte(`"exchangeVersion": 1`), []byte(`"exchangeVersion": 1, "exchangeVersion": 1`), 1),
		"surrogate":         bytes.Replace(valid, []byte("backend-review"), []byte(`bad\uD800`), 1),
		"traversal":         bytes.Replace(valid, []byte("backend-review"), []byte("../private"), 1),
		"unknown":           bytes.Replace(valid, []byte(`"exchangeVersion": 1`), []byte(`"future": true, "exchangeVersion": 1`), 1),
		"too deeply nested": []byte(strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if result := Decode(data, nil, "imported"); result.Code == CodeValid || result.Candidate != nil {
				t.Fatalf("accepted: %#v", result)
			}
		})
	}
}

func TestExportRefusesOpaqueInactiveOverlayRatherThanDroppingIt(t *testing.T) {
	candidate := fixtureProfile(t)
	candidate.Overlays["future"] = profile.OverlayPayload{Version: 9, Support: "inactive-unknown"}
	if data, _, err := Export(candidate); err == nil || data != nil {
		t.Fatalf("opaque overlay exported: %v\n%s", err, data)
	}
}

func TestExportRefusesUnknownThirdCommonCapability(t *testing.T) {
	candidate := fixtureProfile(t)
	candidate.Common["future"] = profile.CommonPayload{Version: 1, Selection: json.RawMessage(`{}`)}
	if data, _, err := Export(candidate); err == nil || data != nil {
		t.Fatalf("unknown common capability exported: %v\n%s", err, data)
	}
}

func TestVersionOneRejectsEveryPresentPathsField(t *testing.T) {
	base := `{"exchangeVersion":1,"profile":{"common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}%s},"overlays":{"devin":{"version":1}}},"requirements":{"sources":[],"authentications":[]}}`
	for name, field := range map[string]string{
		"null":  `,"paths":null`,
		"zero":  `,"paths":{"version":0,"selection":null}`,
		"empty": `,"paths":{"version":1,"selection":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			result := Decode([]byte(fmt.Sprintf(base, field)), nil, "imported")
			if result.Code != CodeUnsupportedContent || result.Candidate != nil {
				t.Fatalf("present v1 paths accepted: %#v", result)
			}
		})
	}
}

func TestVersionTwoPathBindingsDoNotLeakAndRoundTrip(t *testing.T) {
	candidate := fixtureProfile(t)
	paths, err := commonprofile.EncodePathSelection(commonprofile.PathSelection{Entries: []commonprofile.PathEntry{
		{ID: "workspace-data", Access: launch.PathAccessReadOnly, Type: launch.PathTypeDirectory, Reference: commonprofile.PathReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "fixtures/data"}},
		{ID: "local-cache", Access: launch.PathAccessReadWrite, Type: launch.PathTypeDirectory, Reference: commonprofile.PathReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: "/Users/private/cache"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.PathsCapabilityID] = profile.CommonPayload{Version: 1, Selection: paths}
	exported, report, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if report.PathBindings != 1 || bytes.Contains(exported, []byte("/Users/private")) || !bytes.Contains(exported, []byte(`"pathBinding": "path-1"`)) {
		t.Fatalf("unsafe export (%#v): %s", report, exported)
	}
	bindings := []byte(`{"bindingVersion":2,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{"path-1":"/Users/restored/cache"}}`)
	result := Decode(exported, bindings, "imported")
	if result.Code != CodeValid || result.Candidate == nil || result.RequiredPaths != 1 {
		t.Fatalf("decode = %#v", result)
	}
	selection, err := commonprofile.DecodePathSelection(result.Candidate.Common[commonprofile.PathsCapabilityID].Selection)
	if err != nil || selection.Entries[0].Reference.Path != "/Users/restored/cache" || selection.Entries[1].Reference.Path != "fixtures/data" {
		t.Fatalf("paths = %#v, %v", selection, err)
	}
}

func TestVersionTwoExecutableBindingsDoNotLeakAndRoundTrip(t *testing.T) {
	candidate := fixtureProfile(t)
	executables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{
		{ID: "fixed", Reference: commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceFixedSearchName), Name: "git"}},
		{ID: "repo", Reference: commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceWorkspaceRelative), Path: "bin/tool"}},
		{ID: "private", Reference: commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceLocalAbsolute), Path: "/Users/private/bin/tool"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: 1, Selection: executables}
	exported, report, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if report.ExecutableBindings != 1 || bytes.Contains(exported, []byte("/Users/private")) || !bytes.Contains(exported, []byte(`"executableBinding": "executable-1"`)) {
		t.Fatalf("report=%#v exchange=%s", report, exported)
	}
	bindings := []byte(`{"bindingVersion":2,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{"executable-1":"/Users/restored/bin/tool"}}`)
	result := Decode(exported, bindings, "restored")
	if result.Code != CodeValid || result.Candidate == nil || result.RequiredExecutables != 1 {
		t.Fatalf("result = %#v", result)
	}
	selection, err := commonprofile.DecodeExecutableSelection(result.Candidate.Common[commonprofile.ExecutablesCapabilityID].Selection)
	if err != nil || len(selection.Entries) != 3 || selection.Entries[1].ID != "private" || selection.Entries[1].Reference.Path != "/Users/restored/bin/tool" {
		t.Fatalf("executables = %#v, %v", selection, err)
	}
	if got := Decode(exported, []byte(`{"bindingVersion":2,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{}}`), "restored"); got.Code != CodeBindingRequired {
		t.Fatalf("missing binding = %#v", got)
	}
}

func TestVersionTwoExecutableOptionalFieldPresenceIsStrict(t *testing.T) {
	candidate := fixtureProfile(t)
	executables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{{
		ID: "fixed", Reference: commonprofile.ExecutableReference{Kind: string(launch.ExecutableReferenceFixedSearchName), Name: "git"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: 1, Selection: executables}
	exported, _, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []byte(`{"bindingVersion":2,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{}}`)
	if got := Decode(exported, bindings, "restored"); got.Code != CodeValid {
		t.Fatalf("omitted empty requirement rejected: %#v", got)
	}
	var envelope map[string]any
	if err := json.Unmarshal(exported, &envelope); err != nil {
		t.Fatal(err)
	}
	requirements := envelope["requirements"].(map[string]any)
	requirements["executables"] = []any{}
	explicitEmpty, _ := json.Marshal(envelope)
	if got := Decode(explicitEmpty, bindings, "restored"); got.Code != CodeValid {
		t.Fatalf("explicit empty requirement rejected: %#v", got)
	}
	requirements["executables"] = nil
	explicitNull, _ := json.Marshal(envelope)
	if got := Decode(explicitNull, bindings, "restored"); got.Code != CodeInvalidStructure {
		t.Fatalf("null executable requirements accepted: %#v", got)
	}
	if got := Decode(explicitEmpty, []byte(`{"bindingVersion":2,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":null}`), "restored"); got.Code != CodeBindingInvalid {
		t.Fatalf("null executable bindings accepted: %#v", got)
	}
}

func TestEveryKnownFieldHasClassification(t *testing.T) {
	fields := KnownFieldClassifications()
	for _, name := range []string{"version", "name", "target", "categories", "common", "common.skills.version", "common.skills.selection", "common.skills.source", "common.skills.relativePath", "common.workspace.version", "common.workspace.selection", "common.workspace.access", "overlays", "overlays.devin.version", "overlays.codex.version", "overlays.codex.authRef", "skill-assets", "secret-values", "provider-records", "resolved-host-paths", "runtime-state", "repository-session-state", "unknown-fields"} {
		if fields[name] == "" {
			t.Fatalf("missing classification for %s", name)
		}
	}
}

func fixtureProfile(t *testing.T) profile.Profile {
	t.Helper()
	skills, err := json.Marshal([]map[string]string{
		{"source": "shared-agents", "relativePath": "backend-review"},
		{"source": "devin-config", "relativePath": "frontend-review"},
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace := json.RawMessage(`{"access":"read-write"}`)
	return profile.Profile{Version: 3, SourceVersion: 3, Name: "source", Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: skills}, "workspace": {Version: 1, Selection: workspace},
	}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}, "codex": {Version: 1, AuthRef: "work"}}}
}

func FuzzDecodeBounded(f *testing.F) {
	candidate := profile.Profile{Version: 3, SourceVersion: 3, Name: "source", Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: json.RawMessage(`[]`)}, "workspace": {Version: 1, Selection: json.RawMessage(`{"access":"read-only"}`)},
	}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}}}
	seed, _, _ := Export(candidate)
	f.Add(seed)
	f.Add([]byte(`{"exchangeVersion":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxBytes+1 {
			data = data[:MaxBytes+1]
		}
		result := Decode(data, nil, "fuzzed")
		if result.Code != CodeValid && result.Candidate != nil {
			t.Fatal("invalid input produced candidate")
		}
	})
}

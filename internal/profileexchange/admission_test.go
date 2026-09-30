package profileexchange

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestDocumentSemanticsAreCheckedBeforeBindings(t *testing.T) {
	seed, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*document)
		code   Code
	}{
		{"unknown-overlay", func(d *document) { d.Profile.Overlays["unsupported"] = exchangeOverlay{Version: 1} }, CodeUnsupportedContent},
		{"overlay-version", func(d *document) { d.Profile.Overlays["devin"] = exchangeOverlay{Version: 999} }, CodeUnsupportedContent},
		{"no-overlay", func(d *document) { d.Profile.Overlays = nil; d.Requirements.Authentications = []requirement{} }, CodeInvalidStructure},
		{"path-access", func(d *document) {
			d.Profile.Common.Paths.Selection = []exchangePathEntry{{ID: "cache", Access: "delete", Type: "file", Reference: exchangePathReference{Kind: "workspace-relative", Path: "cache"}}}
		}, CodeInvalidStructure},
		{"path-escape", func(d *document) {
			d.Profile.Common.Paths.Selection = []exchangePathEntry{{ID: "cache", Access: "read-only", Type: "file", Reference: exchangePathReference{Kind: "workspace-relative", Path: "../cache"}}}
		}, CodeInvalidStructure},
		{"executable-name", func(d *document) {
			d.Profile.Common.Executables.Selection = []exchangeExecutableEntry{{ID: "tool", Reference: exchangeExecutableReference{Kind: "fixed-search-name", Name: "../tool"}}}
		}, CodeInvalidStructure},
		{"environment-reserved", func(d *document) {
			d.Profile.Common.Environment.Selection = []exchangeEnvironmentEntry{{ID: "mode", Destination: "HOME", Scope: "attached-process-tree", Source: exchangeEnvironmentSource{Kind: "host-environment", Name: "SOURCE_HOME"}, Classification: "non-secret"}}
		}, CodeInvalidStructure},
		{"environment-scope", func(d *document) {
			d.Profile.Common.Environment.Selection = []exchangeEnvironmentEntry{{ID: "mode", Destination: "MODE", Scope: "all-processes", Source: exchangeEnvironmentSource{Kind: "host-environment", Name: "SOURCE_MODE"}, Classification: "non-secret"}}
		}, CodeInvalidStructure},
		{"mcp-missing-reference", func(d *document) {
			d.Profile.Common.MCP = &exchangeMCP{Version: 1, Selection: json.RawMessage(`{"servers":[{"id":"tool","transport":"stdio","executableRef":"missing","arguments":[],"inputRefs":[],"environmentRefs":[]}]}`)}
		}, CodeInvalidStructure},
		{"instruction-hidden-path", func(d *document) {
			d.Profile.Common.Instructions = &exchangeInstructions{Version: 1, Selection: []exchangeInstructionReference{{SourceBinding: "source-1", RelativePath: ".hidden.md"}}}
		}, CodeUnsafePath},
		{"source-kind-conflict", func(d *document) {
			d.Profile.Common.Instructions = &exchangeInstructions{Version: 1, Selection: []exchangeInstructionReference{{SourceBinding: "source-1", RelativePath: "review.md"}}}
		}, CodeInvalidStructure},
		{"undeclared-source", func(d *document) {
			d.Profile.Common.Skills.Selection[0].SourceBinding = "source-99"
		}, CodeInvalidStructure},
	}
	bindings := [][]byte{nil, []byte(`{"bindingVersion":3,"sources":{},"authentications":{},"paths":{},"executables":{},"environment":{}}`), []byte(`{"bindingVersion":3,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{},"environment":{}}`)}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d document
			if err := json.Unmarshal(seed, &d); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&d)
			encoded, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			for i, b := range bindings {
				got := Decode(encoded, b, "imported")
				if got.Code != tc.code || got.Candidate != nil {
					t.Errorf("binding state %d: got %#v; want %s", i, got, tc.code)
				}
			}
		})
	}
}

func TestBindingFieldNamesAreCanonical(t *testing.T) {
	doc, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"bindingVersion":3,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{},"environment":{}}`
	for _, field := range []string{"bindingVersion", "sources", "authentications", "paths", "executables", "environment"} {
		t.Run(field, func(t *testing.T) {
			mutated := strings.Replace(canonical, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1)
			if got := Decode(doc, []byte(mutated), "imported"); got.Code != CodeBindingInvalid || got.Candidate != nil {
				t.Fatalf("accepted field alias: %#v", got)
			}
		})
	}
	for _, mutated := range []string{
		strings.Replace(canonical, `"sources":`, `"Sources":{"source-1":"shared-agents"},"sources":`, 1),
		strings.Replace(strings.Replace(canonical, `"bindingVersion":3`, `"bindingVersion":2`, 1), `"environment":{}`, `"Environment":null`, 1),
	} {
		if got := Decode(doc, []byte(mutated), "imported"); got.Code != CodeBindingInvalid || got.Candidate != nil {
			t.Fatalf("accepted alias collision/version field: %#v", got)
		}
	}
}

func TestExportRespectsImportBindingClassLimits(t *testing.T) {
	for _, capability := range []string{"paths", "executables", "environment"} {
		for _, count := range []int{maxBindings, maxBindings + 1} {
			t.Run(fmt.Sprintf("%s/%d", capability, count), func(t *testing.T) {
				candidate := fixtureProfile(t)
				paths := commonprofile.PathSelection{Entries: []commonprofile.PathEntry{}}
				executables := commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{}}
				environment := commonprofile.EnvironmentSelection{Entries: []commonprofile.EnvironmentEntry{}}
				for i := 0; i < count; i++ {
					id := fmt.Sprintf("entry-%d", i)
					paths.Entries = append(paths.Entries, commonprofile.PathEntry{ID: id, Access: launch.PathAccessReadOnly, Type: launch.PathTypeFile, Reference: commonprofile.PathReference{Kind: "local-absolute", Path: "/synthetic/" + id}})
					executables.Entries = append(executables.Entries, commonprofile.ExecutableEntry{ID: id, Reference: commonprofile.ExecutableReference{Kind: "local-absolute", Path: "/synthetic/" + id}})
					environment.Entries = append(environment.Entries, commonprofile.EnvironmentEntry{ID: id, Destination: fmt.Sprintf("DEST_%d", i), Scope: "attached-process-tree", Required: true, Classification: "secret", Source: commonprofile.EnvironmentSource{Kind: "secret-reference", Provider: "host-environment", Reference: fmt.Sprintf("SOURCE_%d", i)}})
				}
				var raw json.RawMessage
				var err error
				switch capability {
				case "paths":
					raw, err = commonprofile.EncodePathSelection(paths)
				case "executables":
					raw, err = commonprofile.EncodeExecutableSelection(executables)
				case "environment":
					raw, err = commonprofile.EncodeEnvironmentSelection(environment)
				}
				if err != nil {
					t.Fatal(err)
				}
				candidate.Common[capability] = profile.CommonPayload{Version: 1, Selection: raw}
				encoded, _, err := Export(candidate)
				if count > maxBindings {
					if err == nil || encoded != nil {
						t.Fatal("export emitted a document its importer rejects")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := Decode(encoded, nil, "imported"); got.Code != CodeBindingRequired {
					t.Fatalf("export did not pass symbolic admission: %#v", got)
				}
			})
		}
	}
}

func TestSymbolicRepresentativesStayDistinctAndNeverBecomeCandidateValues(t *testing.T) {
	seed, _, err := Export(fixtureProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(seed, &doc); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		pathID, executableID, environmentID := fmt.Sprintf("path-%d", i), fmt.Sprintf("executable-%d", i), fmt.Sprintf("environment-%d", i)
		doc.Requirements.Paths = append(doc.Requirements.Paths, requirement{ID: pathID, Kind: "local-absolute"})
		doc.Requirements.Executables = append(doc.Requirements.Executables, requirement{ID: executableID, Kind: "local-absolute"})
		doc.Requirements.Environment = append(doc.Requirements.Environment, requirement{ID: environmentID, Kind: "host-environment-secret-reference"})
		doc.Profile.Common.Paths.Selection = append(doc.Profile.Common.Paths.Selection, exchangePathEntry{ID: pathID, Access: "read-only", Type: "file", Reference: exchangePathReference{Kind: "bound", PathBinding: pathID}})
		doc.Profile.Common.Executables.Selection = append(doc.Profile.Common.Executables.Selection, exchangeExecutableEntry{ID: executableID, Reference: exchangeExecutableReference{Kind: "bound", ExecutableBinding: executableID}})
		doc.Profile.Common.Environment.Selection = append(doc.Profile.Common.Environment.Selection, exchangeEnvironmentEntry{ID: environmentID, Destination: fmt.Sprintf("TOKEN_%d", i), Scope: "attached-process-tree", Required: true, Classification: "secret", Source: exchangeEnvironmentSource{Kind: "secret-reference", Provider: "host-environment", ReferenceBinding: environmentID}})
	}
	// The same text under a different reference kind must not collide with a
	// symbolic absolute representative.
	doc.Profile.Common.Paths.Selection = append(doc.Profile.Common.Paths.Selection, exchangePathEntry{ID: "workspace", Access: "read-only", Type: "file", Reference: exchangePathReference{Kind: "workspace-relative", Path: "acs-exchange-symbolic/path-1"}})
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	bindings := bindingDocument{BindingVersion: 3, Sources: map[string]string{"source-1": "devin-config", "source-2": "shared-agents"}, Authentications: map[string]string{"authentication-1": "personal"}, Paths: map[string]string{"path-1": "/local/path/first", "path-2": "/local/path/second"}, Executables: map[string]string{"executable-1": "/local/tool/first", "executable-2": "/local/tool/second"}, Environment: map[string]string{"environment-1": "FIRST_TOKEN", "environment-2": "SECOND_TOKEN"}}
	partial, err := json.Marshal(bindingDocument{BindingVersion: 3, Sources: bindings.Sources, Authentications: bindings.Authentications, Paths: map[string]string{"path-1": bindings.Paths["path-1"]}, Executables: map[string]string{"executable-1": bindings.Executables["executable-1"]}, Environment: map[string]string{"environment-1": bindings.Environment["environment-1"]}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, partial} {
		if got := Decode(encoded, raw, "imported"); got.Code != CodeBindingRequired || got.Candidate != nil {
			t.Fatalf("unresolved result has candidate: %#v", got)
		}
	}
	complete, err := json.Marshal(bindings)
	if err != nil {
		t.Fatal(err)
	}
	got := Decode(encoded, complete, "imported")
	if got.Code != CodeValid || got.Candidate == nil {
		t.Fatalf("distinct symbols rejected: %#v", got)
	}
	paths, err := commonprofile.DecodePathSelection(got.Candidate.Common["paths"].Selection)
	if err != nil || paths.Entries[0].Reference.Path != "/local/path/first" || paths.Entries[1].Reference.Path != "/local/path/second" {
		t.Fatalf("path bindings changed: %#v, %v", paths, err)
	}
	executables, err := commonprofile.DecodeExecutableSelection(got.Candidate.Common["executables"].Selection)
	if err != nil || executables.Entries[0].Reference.Path != "/local/tool/first" || executables.Entries[1].Reference.Path != "/local/tool/second" {
		t.Fatalf("executable bindings changed: %#v, %v", executables, err)
	}
	environment, err := commonprofile.DecodeEnvironmentSelection(got.Candidate.Common["environment"].Selection)
	if err != nil || environment.Entries[0].Source.Reference != "FIRST_TOKEN" || environment.Entries[1].Source.Reference != "SECOND_TOKEN" {
		t.Fatalf("environment bindings changed: %#v, %v", environment, err)
	}
	bindings.Paths["path-2"] = bindings.Paths["path-1"]
	aliased, err := json.Marshal(bindings)
	if err != nil {
		t.Fatal(err)
	}
	if got := Decode(encoded, aliased, "imported"); got.Code != CodeBindingInvalid || got.Candidate != nil {
		t.Fatalf("local alias accepted: %#v", got)
	}
	// A repeated symbolic destination is invalid even before local bindings.
	doc.Profile.Common.Paths.Selection[1].Reference.PathBinding = "path-1"
	doc.Requirements.Paths = doc.Requirements.Paths[:1]
	duplicated, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := Decode(duplicated, nil, "imported"); got.Code != CodeInvalidStructure || got.Candidate != nil {
		t.Fatalf("symbolic alias accepted: %#v", got)
	}
}

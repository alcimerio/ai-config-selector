package commonprofile_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
)

const minimalProfile = `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1},"codex":{"version":1,"authRef":"work"}}}`

const completeProfile = `{"version":3,"name":"example","common":{
"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"}]},
"instructions":{"version":1,"selection":[{"source":"acs-instructions","relativePath":"guide.md"}]},
"workspace":{"version":1,"selection":{"access":"read-write"}},
"paths":{"version":1,"selection":{"entries":[{"id":"settings","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"config.json"}}]}},
"executables":{"version":1,"selection":{"entries":[{"id":"server-bin","reference":{"kind":"fixed-search-name","name":"tool"}}]}},
"environment":{"version":1,"selection":{"entries":[{"id":"token","destination":"MCP_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_CODEC_TOKEN"},"required":true,"classification":"secret"}]}},
"mcp":{"version":1,"selection":{"servers":[{"id":"tool","transport":"stdio","executableRef":"server-bin","arguments":[{"kind":"path","ref":"settings"}],"inputRefs":["settings"],"environmentRefs":["token"],"disabledTools":["remove_issue"]}]}}
},"overlays":{"devin":{"version":1},"codex":{"version":1,"authRef":"work"}}}`

type strictCodec interface {
	profile.Codec
	DecodeNamed(string, []byte) (profile.Profile, error)
}

func TestNeutralCodecPreservesAdapterAdmissionAndCanonicalBytes(t *testing.T) {
	codec, err := commonprofile.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	editor, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codex.New(codex.Config{BinaryPath: "/not-installed/codex", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		body    string
		version int
		valid   bool
	}{
		{"v1", `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"z"},{"source":"devin-config","relativePath":"a"}]}`, 1, true},
		{"v2", `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[]}}}`, 2, true},
		{"v3 defaults", minimalProfile, 3, true},
		{"v3 all capabilities", completeProfile, 3, true},
		{"v3 codex only", strings.Replace(minimalProfile, `"devin":{"version":1},`, "", 1), 3, true},
		{"v3 inactive unknown overlay", strings.Replace(minimalProfile, `"devin":{"version":1}`, `"future":{"version":1}`, 1), 3, true},
		{"v3 inactive Codex version", strings.Replace(minimalProfile, `"codex":{"version":1`, `"codex":{"version":7`, 1), 3, true},
		{"v3 inactive Devin extension", strings.Replace(minimalProfile, `"devin":{"version":1}`, `"devin":{"version":1,"future":true}`, 1), 3, true},
		{"duplicate field", strings.Replace(minimalProfile, `"version":3`, `"version":3,"version":3`, 1), 3, false},
		{"unknown envelope field", strings.Replace(minimalProfile, `"version":3`, `"version":3,"future":true`, 1), 3, false},
		{"unknown capability", strings.Replace(minimalProfile, `"skills":`, `"future":`, 1), 3, false},
		{"unsupported capability version", strings.Replace(minimalProfile, `"skills":{"version":1`, `"skills":{"version":2`, 1), 3, false},
		{"unsupported envelope version", strings.Replace(minimalProfile, `"version":3`, `"version":4`, 1), 4, false},
		{"mismatched name", strings.Replace(minimalProfile, `"name":"example"`, `"name":"other"`, 1), 3, false},
		{"null selection", strings.Replace(minimalProfile, `"selection":[]`, `"selection":null`, 1), 3, false},
		{"noncanonical case", strings.Replace(minimalProfile, `"skills":`, `"Skills":`, 1), 3, false},
		{"trailing data", minimalProfile + `{}`, 3, false},
		{"unsafe skill path", strings.Replace(completeProfile, `"relativePath":"review"`, `"relativePath":"../review"`, 1), 3, false},
		{"dangling MCP reference", strings.Replace(completeProfile, `"executableRef":"server-bin"`, `"executableRef":"missing"`, 1), 3, false},
		{"invalid instruction source", strings.Replace(completeProfile, `"source":"acs-instructions"`, `"source":"shared-agents"`, 1), 3, false},
		{"legacy common-only category", `{"version":2,"name":"example","target":"devin","categories":{"workspace":{"schemaVersion":1,"selection":{"access":"read-only"}}}}`, 2, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := codec.DecodeNamed("example", []byte(test.body))
			if (gotErr == nil) != test.valid {
				t.Fatalf("admission = %v; want valid=%v", gotErr, test.valid)
			}
			adapters := []strictCodec{editor.Categories()}
			if test.version >= 3 {
				adapters = append(adapters, codexTarget.Categories())
			}
			for _, adapter := range adapters {
				want, wantErr := adapter.DecodeNamed("example", []byte(test.body))
				if errorText(gotErr) != errorText(wantErr) || !reflect.DeepEqual(got, want) {
					t.Fatalf("strict codec differs: got=%+v err=%v; want=%+v err=%v", got, gotErr, want, wantErr)
				}
				// Decode remains compatible too; exact-byte admission still belongs
				// to DecodeNamed, as it did before this extraction.
				if test.version <= 3 {
					decoded, decodeErr := codec.Decode([]byte(test.body))
					active, activeErr := adapter.Decode([]byte(test.body))
					if errorText(decodeErr) != errorText(activeErr) || !reflect.DeepEqual(decoded, active) {
						t.Fatalf("Decode differs: got=%v want=%v", decodeErr, activeErr)
					}
				}
				if gotErr != nil {
					continue
				}
				exported, report, exportErr := profileexchange.Export(got)
				wantExport, wantReport, wantExportErr := profileexchange.Export(want)
				if errorText(exportErr) != errorText(wantExportErr) || !bytes.Equal(exported, wantExport) || !reflect.DeepEqual(report, wantReport) {
					t.Fatalf("exchange output or classification differs: got=%v want=%v", exportErr, wantExportErr)
				}
				_, actual, err := profile.Canonicalize(codec, got)
				if err != nil {
					t.Fatal(err)
				}
				_, expected, err := profile.Canonicalize(adapter, want)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("canonical bytes differ: %v\ngot %s\nwant %s", err, actual, expected)
				}
				if len(actual) == 0 || actual[len(actual)-1] != '\n' {
					t.Fatal("canonical newline lost")
				}
			}
			if gotErr != nil {
				return
			}
			if got.SourceVersion != test.version {
				t.Fatalf("source version=%d want=%d", got.SourceVersion, test.version)
			}
			if test.version < 3 {
				if got.Version != 2 || got.Common != nil || len(got.Categories) != 1 {
					t.Fatalf("legacy behavior migrated implicitly: %+v", got)
				}
			} else if len(got.Common) != 7 {
				t.Fatalf("common defaults lost: %+v", got.Common)
			}
		})
	}
}

func TestNeutralCodecRoundTripsAllCapabilitiesWithoutHomeResources(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "absent-home")
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	t.Setenv("HOST_CODEC_TOKEN", "must-not-be-read-or-exported")
	codec, err := commonprofile.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := codec.DecodeNamed("example", []byte(completeProfile))
	if err != nil {
		t.Fatal(err)
	}
	document, report, err := profileexchange.Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if report.SourceBindings != 2 || report.AuthenticationBindings != 1 || report.EnvironmentBindings != 1 {
		t.Fatalf("binding classification drift: %+v", report)
	}
	if bytes.Contains(document, []byte("must-not-be-read-or-exported")) {
		t.Fatal("exchange read an environment value")
	}
	bindings := []byte(`{"bindingVersion":3,"sources":{"source-1":"acs-instructions","source-2":"shared-agents"},"authentications":{"authentication-1":"work"},"paths":{},"executables":{},"environment":{"environment-1":"HOST_CODEC_TOKEN"}}`)
	result := profileexchange.Decode(document, bindings, "restored")
	if result.Code != profileexchange.CodeValid || result.Candidate == nil {
		t.Fatalf("roundtrip decode = %+v", result)
	}
	candidate.Name = "restored"
	_, expected, err := profile.Canonicalize(codec, candidate)
	if err != nil {
		t.Fatal(err)
	}
	_, actual, err := profile.Canonicalize(codec, *result.Candidate)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("roundtrip canonical bytes differ: %v\ngot %s\nwant %s", err, actual, expected)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("passive codec created home resources: %v", err)
	}
}

func TestNeutralCodecOptionalDefaultsMatchStoredSchema(t *testing.T) {
	codec, err := commonprofile.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := codec.DecodeNamed("example", []byte(minimalProfile))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"skills": "[]", "instructions": "[]", "workspace": `{"access":"read-only"}`, "paths": `{"entries":[]}`, "executables": `{"entries":[]}`, "environment": `{"entries":[]}`, "mcp": `{"servers":[]}`} {
		payload := candidate.Common[id]
		if payload.Version != 1 || !json.Valid(payload.Selection) || string(payload.Selection) != want {
			t.Fatalf("%s default=%+v want version 1 %s", id, payload, want)
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

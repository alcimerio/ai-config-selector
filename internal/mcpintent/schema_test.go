package mcpintent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
)

const validSelection = `{"servers":[{"id":"server-a","transport":"stdio","executableRef":"server-bin","arguments":[{"kind":"environment","ref":"config-arg"},{"kind":"path","ref":"config-file"}],"inputRefs":["config-file"],"environmentRefs":["api-token","config-arg"],"disabledTools":["remove_issue","write_file"]}]}`

func TestDecodeCanonicalizesReferenceListsAndPreservesArgumentOrder(t *testing.T) {
	selection, err := Decode(json.RawMessage(validSelection))
	if err != nil {
		t.Fatal(err)
	}
	server := selection.Servers[0]
	if server.ID != "server-a" || server.Transport != TransportStdio || server.ExecutableRef != "server-bin" {
		t.Fatalf("server = %#v", server)
	}
	if len(server.Arguments) != 2 || server.Arguments[0] != (Argument{Kind: ArgumentEnv, Ref: "config-arg"}) || server.Arguments[1] != (Argument{Kind: ArgumentPath, Ref: "config-file"}) {
		t.Fatalf("argument order changed: %#v", server.Arguments)
	}
	if strings.Join(server.InputRefs, ",") != "config-file" || strings.Join(server.EnvironmentRefs, ",") != "api-token,config-arg" || strings.Join(server.DisabledTools, ",") != "remove_issue,write_file" {
		t.Fatalf("canonical lists = %#v", server)
	}
	encoded, err := Encode(selection)
	if err != nil {
		t.Fatal(err)
	}
	redecoded, err := Decode(encoded)
	if err != nil || len(redecoded.Servers) != 1 || redecoded.Servers[0].Arguments[0] != server.Arguments[0] {
		t.Fatalf("round trip = %#v, %v", redecoded, err)
	}
}

func TestValidateReferencesAllowsSelectedSecretEnvironmentButRejectsSecretArgv(t *testing.T) {
	selection := Selection{Servers: []Server{{ID: "tool", Transport: TransportStdio, ExecutableRef: "exe", Arguments: []Argument{{Kind: ArgumentEnv, Ref: "mode"}}, InputRefs: []string{}, EnvironmentRefs: []string{"credential", "mode"}}}}
	executables := executableintent.Selection{Entries: []executableintent.Entry{{ID: "exe", Reference: executableintent.Reference{Kind: string(executableintent.ReferenceFixedSearchName), Name: "tool"}}}}
	paths := pathintent.Empty()
	environment := environmentintent.Selection{Entries: []environmentintent.Entry{
		{ID: "credential", Destination: "MCP_TOKEN", Scope: environmentintent.ScopeAttachedProcessTree, Source: environmentintent.Source{Kind: environmentintent.SourceSecretReference, Provider: environmentintent.ProviderHostEnvironment, Reference: "HOST_MCP_TOKEN"}, Required: true, Classification: environmentintent.ClassificationSecret},
		{ID: "mode", Destination: "MCP_MODE", Scope: environmentintent.ScopeAttachedProcessTree, Source: environmentintent.Source{Kind: environmentintent.SourceHostEnvironment, Name: "HOST_MCP_MODE"}, Classification: environmentintent.ClassificationNonSecret},
	}}
	if err := ValidateReferences(selection, executables, paths, environment); err != nil {
		t.Fatalf("selected secret environment delivery was rejected: %v", err)
	}
	selection.Servers[0].Arguments[0].Ref = "credential"
	if err := ValidateReferences(selection, executables, paths, environment); err == nil {
		t.Fatal("secret-classified argv reference was accepted")
	}
}

func TestEmptySelectionHasCanonicalEmptyArray(t *testing.T) {
	encoded, err := Encode(Empty())
	if err != nil || string(encoded) != `{"servers":[]}` {
		t.Fatalf("empty encoding = %s, %v", encoded, err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Servers == nil || len(decoded.Servers) != 0 {
		t.Fatalf("empty decoding = %#v, %v", decoded, err)
	}
}

func TestNonemptyServerWithNoArgumentsRoundTripsAndCanonicalizesIdempotently(t *testing.T) {
	input := json.RawMessage(`{"servers":[{"id":"tool","transport":"stdio","executableRef":"server-bin","arguments":[],"inputRefs":[],"environmentRefs":[]}]}`)
	selection, err := Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Servers[0].Arguments == nil {
		t.Fatal("empty argument list became nil")
	}
	encoded, err := Encode(selection)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Servers[0].Arguments == nil || len(decoded.Servers[0].Arguments) != 0 {
		t.Fatalf("empty argv round trip = %#v, %v", decoded, err)
	}
	canonical, err := Canonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	encodedAgain, err := Encode(canonical)
	if err != nil || string(encodedAgain) != string(encoded) {
		t.Fatalf("canonical encoding changed: first=%s second=%s err=%v", encoded, encodedAgain, err)
	}
}

func TestDecodeRejectsAmbiguousOrUnsupportedMCPIntent(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"duplicate top-level key", `{"servers":[],"servers":[]}`},
		{"duplicate server key", strings.Replace(validSelection, `"id":"server-a",`, `"id":"server-a","id":"server-b",`, 1)},
		{"case alias conflicting id", strings.Replace(validSelection, `"id":"server-a",`, `"id":"server-a","ID":"other",`, 1)},
		{"case alias conflicting argument list", strings.Replace(validSelection, `"arguments":[`, `"arguments":[{"kind":"path","ref":"config-file"}],"ARGUMENTS":[`, 1)},
		{"case alias top-level servers", `{"SERVERS":[]}`},
		{"escaped case alias", strings.Replace(validSelection, `"id":"server-a",`, `"id":"server-a","\u0049D":"other",`, 1)},
		{"escaped duplicate field", strings.Replace(validSelection, `"id":"server-a",`, `"id":"server-a","\u0069d":"other",`, 1)},
		{"unknown field", strings.Replace(validSelection, `"id":"server-a",`, `"future":true,"id":"server-a",`, 1)},
		{"null server list", `{"servers":null}`},
		{"null required list", strings.Replace(validSelection, `"inputRefs":["config-file"]`, `"inputRefs":null`, 1)},
		{"null optional list", strings.Replace(validSelection, `,"disabledTools":["remove_issue","write_file"]`, `,"disabledTools":null`, 1)},
		{"null argument", strings.Replace(validSelection, `{"kind":"path","ref":"config-file"}`, `null`, 1)},
		{"literal argument", strings.Replace(validSelection, `{"kind":"path","ref":"config-file"}`, `"--config=token"`, 1)},
		{"remote transport", strings.Replace(validSelection, `"stdio"`, `"http"`, 1)},
		{"duplicate server id", `{"servers":[{"id":"x","transport":"stdio","executableRef":"e","arguments":[],"inputRefs":[],"environmentRefs":[]},{"id":"x","transport":"stdio","executableRef":"e","arguments":[],"inputRefs":[],"environmentRefs":[]}]}`},
		{"duplicate argument ref key", strings.Replace(validSelection, `"ref":"config-file"`, `"ref":"config-file","ref":"config-arg"`, 1)},
		{"duplicate input ref", strings.Replace(validSelection, `"inputRefs":["config-file"]`, `"inputRefs":["config-file","config-file"]`, 1)},
		{"invalid identifier", strings.Replace(validSelection, `"id":"server-a"`, `"id":"../bad"`, 1)},
		{"invalid tool name", strings.Replace(validSelection, `"write_file"`, `"write file"`, 1)},
		{"trailing JSON", validSelection + `{}`},
		{"unpaired high surrogate", strings.Replace(validSelection, `"server-a"`, `"server-\uD800"`, 1)},
		{"unpaired low surrogate", strings.Replace(validSelection, `"server-a"`, `"server-\uDC00"`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(json.RawMessage(test.data)); err == nil {
				t.Fatalf("Decode(%s) unexpectedly succeeded", test.data)
			}
		})
	}
	invalidUTF8 := append([]byte(`{"servers":[{"id":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"transport":"stdio"}]}`)...)
	if _, err := Decode(invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 unexpectedly succeeded")
	}
}

func TestCanonicalEnforcesBounds(t *testing.T) {
	selection := Empty()
	selection.Servers = make([]Server, MaximumServers+1)
	if _, err := Canonical(selection); err == nil {
		t.Fatal("oversized server list unexpectedly succeeded")
	}
	selection = Empty()
	selection.Servers = []Server{{ID: "server", Transport: TransportStdio, ExecutableRef: "exe", Arguments: make([]Argument, MaximumArgumentsPerServer+1), InputRefs: []string{}, EnvironmentRefs: []string{}}}
	if _, err := Canonical(selection); err == nil {
		t.Fatal("oversized argument list unexpectedly succeeded")
	}
}

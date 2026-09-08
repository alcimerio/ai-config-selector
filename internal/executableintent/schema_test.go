package executableintent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmptySelectionRoundTripsAsCanonicalArray(t *testing.T) {
	for name, selection := range map[string]Selection{"empty": Empty(), "zero": {}} {
		t.Run(name, func(t *testing.T) {
			encoded, err := Encode(selection)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != `{"entries":[]}` {
				t.Fatalf("encoded = %s", encoded)
			}
			if _, err := Decode(encoded); err != nil {
				t.Fatalf("decode canonical empty: %v", err)
			}
		})
	}
}

func TestExecutableSelectionCanonicalizesAndRejectsMalformedIntent(t *testing.T) {
	selection := Selection{Entries: []Entry{
		{ID: "workspace-tool", Reference: Reference{Kind: string(ReferenceWorkspaceRelative), Path: "bin/../bin/tool"}},
		{ID: "fixed-tool", Reference: Reference{Kind: string(ReferenceFixedSearchName), Name: "tool"}},
	}}
	encoded, err := Encode(selection)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"entries":[{"id":"fixed-tool","reference":{"kind":"fixed-search-name","name":"tool"}},{"id":"workspace-tool","reference":{"kind":"workspace-relative","path":"bin/tool"}}]}` {
		t.Fatalf("encoded = %s", encoded)
	}

	invalid := []string{
		`null`, `{}`, `{"entries":null}`, `{"entries":[],"future":true}`, `{"entries":[]} trailing`,
		`{"entries":[{"id":"UPPER","reference":{"kind":"fixed-search-name","name":"tool"}}]}`,
		`{"entries":[{"id":"tool","reference":{"kind":"fixed-search-name","name":"a/b"}}]}`,
		`{"entries":[{"id":"tool","reference":{"kind":"workspace-relative","path":"../tool"}}]}`,
		`{"entries":[{"id":"tool","reference":{"kind":"local-absolute","path":"relative"}}]}`,
		`{"entries":[{"id":"a","reference":{"kind":"fixed-search-name","name":"tool"}},{"id":"b","reference":{"kind":"fixed-search-name","name":"tool"}}]}`,
	}
	for _, input := range invalid {
		if _, err := Decode(json.RawMessage(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	tooMany := Selection{Entries: make([]Entry, MaximumEntries+1)}
	if _, err := Encode(tooMany); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("oversize error = %v", err)
	}
}

package environmentintent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnvironmentSelectionCanonicalAndStrict(t *testing.T) {
	input := json.RawMessage(`{"entries":[{"id":"token","destination":"SERVICE_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN"},"required":true,"classification":"secret"},{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_BUILD_MODE"},"required":false,"classification":"non-secret"}]}`)
	selection, err := Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Entries) != 2 || selection.Entries[0].ID != "mode" || selection.Entries[1].ID != "token" {
		t.Fatalf("canonical selection = %#v", selection)
	}
	encoded, err := Encode(selection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "HOST_TOKEN_VALUE") || string(encoded) != `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_BUILD_MODE"},"required":false,"classification":"non-secret"},{"id":"token","destination":"SERVICE_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN"},"required":true,"classification":"secret"}]}` {
		t.Fatalf("encoded = %s", encoded)
	}
}

func TestEnvironmentSelectionRejectsInvalidShapes(t *testing.T) {
	validEntry := `{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE"},"required":false,"classification":"non-secret"}`
	cases := map[string]string{
		"missing entries":       `{}`,
		"null entries":          `{"entries":null}`,
		"unknown selection":     `{"entries":[],"extra":true}`,
		"unknown entry":         `{"entries":[` + strings.TrimSuffix(validEntry, `}`) + `,"extra":true}]}`,
		"missing required":      `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE"},"classification":"non-secret"}]}`,
		"null required":         `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE"},"required":null,"classification":"non-secret"}]}`,
		"mixed source":          `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE","reference":"OTHER"},"required":false,"classification":"non-secret"}]}`,
		"host provider null":    `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE","provider":null},"required":false,"classification":"non-secret"}]}`,
		"host provider empty":   `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE","provider":""},"required":false,"classification":"non-secret"}]}`,
		"host reference null":   `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE","reference":null},"required":false,"classification":"non-secret"}]}`,
		"host reference empty":  `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE","reference":""},"required":false,"classification":"non-secret"}]}`,
		"secret name null":      `{"entries":[{"id":"token","destination":"SERVICE_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN","name":null},"required":true,"classification":"secret"}]}`,
		"secret name empty":     `{"entries":[{"id":"token","destination":"SERVICE_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN","name":""},"required":true,"classification":"secret"}]}`,
		"optional secret":       `{"entries":[{"id":"token","destination":"SERVICE_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN"},"required":false,"classification":"secret"}]}`,
		"duplicate destination": `{"entries":[` + validEntry + `,{"id":"other","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"OTHER"},"required":false,"classification":"non-secret"}]}`,
		"trailing":              `{"entries":[]} {}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(json.RawMessage(input)); err == nil {
				t.Fatalf("accepted %s", input)
			}
		})
	}
}

func TestReservedEnvironmentDestinationsShareCompleteInventory(t *testing.T) {
	for _, name := range []string{"HOME", "PATH", "PWD", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "ACS_INTERNAL_STATUS_FD", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND"} {
		if !ReservedDestination(name) {
			t.Errorf("destination %s was not reserved", name)
		}
	}
	for _, name := range []string{"BUILD_MODE", "SERVICE_TOKEN", "HOST_PATH_SOURCE"} {
		if ReservedDestination(name) {
			t.Errorf("destination %s unexpectedly reserved", name)
		}
	}
	// Source names are independently constrained to the POSIX subset and may
	// name a host value whose name would be reserved as a destination.
	selection := Selection{Entries: []Entry{{ID: "source", Destination: "COPIED_PATH", Scope: ScopeAttachedProcessTree, Source: Source{Kind: SourceHostEnvironment, Name: "PATH"}, Classification: ClassificationNonSecret}}}
	if _, err := Canonical(selection); err != nil {
		t.Fatalf("reserved source name was incorrectly rejected: %v", err)
	}
}

package mcpintent

import (
	"strings"
	"testing"
)

func TestMCPJSONPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"depth at limit", strings.Repeat("[", 24) + "0" + strings.Repeat("]", 24), true},
		{"depth beyond limit", strings.Repeat("[", 25) + "0" + strings.Repeat("]", 25), false},
		{"number overflow remains invalid", `1e10000`, false},
		{"duplicate decoded key", `{"x":1,"\u0078":2}`, false},
		{"noncanonical field case", `{"SERVERS":[]}`, false},
		{"trailing value", `{} {}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := uniqueJSON([]byte(tc.input)) == nil; got != tc.valid {
				t.Fatalf("valid=%v, want %v", got, tc.valid)
			}
		})
	}
}

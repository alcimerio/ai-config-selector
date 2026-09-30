package profileinspect

import (
	"strings"
	"testing"
)

func TestInspectionJSONPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"depth at limit", strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64), true},
		{"depth beyond limit", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), false},
		{"number is syntax only", `1e10000`, true},
		{"duplicate decoded key", `{"x":1,"\u0078":2}`, false},
		{"case alias is schema owned", `{"Version":1}`, true},
		{"trailing value", `{} {}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := uniqueJSON([]byte(tc.input)) == nil; got != tc.valid {
				t.Fatalf("valid=%v, want %v", got, tc.valid)
			}
		})
	}
}

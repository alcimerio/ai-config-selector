package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestScanPoliciesAndErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limits      Limits
		reject      func(string) bool
		want        error
	}{
		{name: "one scalar", input: `0`},
		{name: "root empty container", input: `{}`},
		{name: "root-only depth", input: `[0]`, want: ErrLimit},
		{name: "nested value boundary", input: `[0]`, limits: Limits{MaxDepth: 1}},
		{name: "duplicate decoded key", input: `{"x":0,"\u0078":1}`, limits: Limits{MaxDepth: 1}, want: ErrDuplicateKey},
		{name: "unrelated object keys", input: `[{"x":0},{"x":1}]`, limits: Limits{MaxDepth: 2}},
		{name: "single document", input: `{} {}`, want: ErrSyntax},
		{name: "malformed close", input: `[}`, limits: Limits{MaxDepth: 1}, want: ErrSyntax},
		{name: "truncated document", input: `[`, limits: Limits{MaxDepth: 1}, want: ErrSyntax},
		{name: "empty input", input: ``, want: ErrSyntax},
		{name: "key callback", input: `{"\u0078":0}`, limits: Limits{MaxDepth: 1}, reject: func(s string) bool { return s == "x" }, want: ErrRejectedKey},
		{name: "member limit before duplicate", input: `{"x":0,"x":1}`, limits: Limits{MaxDepth: 1, MaxMembers: 1}, want: ErrLimit},
		{name: "key byte limit", input: `{"xx":0}`, limits: Limits{MaxDepth: 1, MaxStringBytes: 1}, want: ErrLimit},
		{name: "decoded UTF8 string bytes", input: `"\u00e9"`, limits: Limits{MaxStringBytes: 1}, want: ErrLimit},
		{name: "decoded UTF8 string boundary", input: `"\u00e9"`, limits: Limits{MaxStringBytes: 2}},
		{name: "tokens include keys", input: `{"x":0}`, limits: Limits{MaxDepth: 1, MaxTokens: 2}, want: ErrLimit},
		{name: "tokens exclude closing delimiter", input: `{"x":0}`, limits: Limits{MaxDepth: 1, MaxTokens: 3}},
		{name: "array limit before next value", input: `[0,}`, limits: Limits{MaxDepth: 1, MaxArray: 1}, want: ErrLimit},
		{name: "array boundary", input: `[0]`, limits: Limits{MaxDepth: 1, MaxArray: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Scan(json.NewDecoder(strings.NewReader(tc.input)), tc.limits, tc.reject)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNumberRepresentationRemainsCallerOwned(t *testing.T) {
	for _, useNumber := range []bool{false, true} {
		decoder := json.NewDecoder(strings.NewReader(`1e10000`))
		if useNumber {
			decoder.UseNumber()
		}
		err := Scan(decoder, Limits{MaxDepth: 0}, nil)
		if (err == nil) != useNumber {
			t.Fatalf("UseNumber=%v: %v", useNumber, err)
		}
	}
}

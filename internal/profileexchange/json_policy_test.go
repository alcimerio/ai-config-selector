package profileexchange

import (
	"fmt"
	"strings"
	"testing"
)

func TestExchangeJSONPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		code        Code
	}{
		{"depth at limit", strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth), CodeValid},
		{"depth beyond limit", strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1), CodeLimitExceeded},
		{"number is syntax only", `1e10000`, CodeValid},
		{"duplicate decoded key", `{"x":1,"\u0078":2}`, CodeDuplicateKey},
		{"case alias is schema owned", `{"Version":1}`, CodeValid},
		{"trailing value", `{} {}`, CodeInvalidJSON},
		{"invalid unicode", `"\ud800"`, CodeInvalidUnicode},
		{"Unicode precedes duplicate key", `{"x":0,"x":"\ud800"}`, CodeInvalidUnicode},
		{"invalid UTF8", "\"\xff\"", CodeInvalidUnicode},
		{"string at limit", `"` + strings.Repeat("x", maxStringBytes) + `"`, CodeValid},
		{"string over limit", `"` + strings.Repeat("x", maxStringBytes+1) + `"`, CodeLimitExceeded},
		{"key over limit precedes duplicate", `{"` + strings.Repeat("x", maxStringBytes+1) + `":1}`, CodeLimitExceeded},
		{"array at limit", `[` + strings.Repeat("0,", maxArray-1) + `0]`, CodeValid},
		{"array over limit", `[` + strings.Repeat("0,", maxArray) + `0]`, CodeLimitExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := preflight([]byte(tc.input)); got != tc.code {
				t.Fatalf("code=%s, want %s", got, tc.code)
			}
		})
	}
	for _, count := range []int{maxMembers, maxMembers + 1} {
		var input strings.Builder
		input.WriteByte('{')
		for i := 0; i < count; i++ {
			if i > 0 {
				input.WriteByte(',')
			}
			fmt.Fprintf(&input, "%q:0", fmt.Sprint(i))
		}
		input.WriteByte('}')
		want := CodeValid
		if count > maxMembers {
			want = CodeLimitExceeded
		}
		if got := preflight([]byte(input.String())); got != want {
			t.Fatalf("%d members: %s, want %s", count, got, want)
		}
	}
}

func TestExchangeJSONTokenBudget(t *testing.T) {
	for _, total := range []int{maxTokens, maxTokens + 1} {
		remaining := total - 1 // root array token
		chunks := []string{}
		for remaining > 0 {
			values := remaining - 1 // this child array token
			if values > maxArray {
				values = maxArray
			}
			if values == 0 {
				chunks = append(chunks, "[]")
			} else {
				chunks = append(chunks, "["+strings.Repeat("0,", values-1)+"0]")
			}
			remaining -= values + 1
		}
		input := []byte("[" + strings.Join(chunks, ",") + "]")
		want := CodeValid
		if total > maxTokens {
			want = CodeLimitExceeded
		}
		if got := preflight(input); got != want {
			t.Fatalf("%d tokens: %s, want %s", total, got, want)
		}
	}
}

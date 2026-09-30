package strictjson

import "testing"

func TestValidUnicode(t *testing.T) {
	for _, input := range []string{`"ordinary"`, `"\u0000"`, `"\uFFFF"`, `"\uD800\uDC00"`, `"\udbff\udfff"`, `"\\ud800"`, `"\\\\ud800"`, `"é🌱"`} {
		if !ValidUnicode([]byte(input)) {
			t.Errorf("rejected %q", input)
		}
	}
	for _, input := range []string{"\"\xff\"", `"\ud800"`, `"\udc00"`, `"\uD800\uD800"`, `"\uD800\u0041"`, `"\uD800\\uDC00"`, `"\uZZZZ"`, `"\u123"`} {
		if ValidUnicode([]byte(input)) {
			t.Errorf("accepted %q", input)
		}
	}
}

func FuzzValidUnicode(f *testing.F) {
	for _, input := range []string{`"ordinary"`, `"\ud800\udc00"`, `"\\ud800"`, `"\uD800"`, "\xff", `{"\u0078":1,"x":2}`} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) { _ = ValidUnicode(input) })
}

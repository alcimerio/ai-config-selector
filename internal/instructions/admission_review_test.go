package instructions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewRejectsDisallowedContent(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":  {},
		"bom":    []byte("\xef\xbb\xbfbody"),
		"escape": []byte("\x1b[31mred"),
		"bell":   []byte("body\a"),
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".acs", "instructions")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "guide.md"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Resolve(home, []Reference{{Source: SourceID, RelativePath: "guide.md"}}); err == nil {
				t.Fatal("accepted content forbidden by the documented input contract")
			}
		})
	}
}

func TestReviewRejectsMalformedUTF8BeforeJSONReplacement(t *testing.T) {
	raw := json.RawMessage("[{\"source\":\"acs-instructions\",\"relativePath\":\"bad\xff.md\"}]")
	if refs, err := Decode(raw); err == nil {
		t.Fatalf("silently changed malformed input to %#v", refs)
	}
}

func TestReviewRejectsUnsafeReferenceText(t *testing.T) {
	for name, path := range map[string]string{
		"newline": "line\nname.md", "nul": "zero\x00name.md", "escape": "\x1b[31mname.md", "invalid_utf8": "bad\xffname.md",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Encode([]Reference{{Source: SourceID, RelativePath: path}}); err == nil {
				t.Fatal("accepted unsafe reference text")
			}
		})
	}
}

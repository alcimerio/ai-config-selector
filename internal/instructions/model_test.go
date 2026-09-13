package instructions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptySelectionIsExplicitArray(t *testing.T) {
	raw, err := Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("empty encoding=%s", raw)
	}
	refs, err := Decode(raw)
	if err != nil || refs == nil || len(refs) != 0 {
		t.Fatalf("decode %s = %#v, %v", raw, refs, err)
	}
	if _, err := Decode(json.RawMessage("null")); err == nil {
		t.Fatal("accepted null selection")
	}
}

func TestResolveCapturesOwnedBoundedBytesAndRejectsLinks(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".acs", "instructions")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nested", "guide.md")
	original := []byte("---\r\ntrigger: manual\r\n---\r\nraw body")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	ref := Reference{Source: SourceID, RelativePath: "nested/guide.md"}
	got, err := Resolve(home, []Reference{ref})
	if err != nil {
		t.Fatal(err)
	}
	if string(got[0].Content) != string(original) {
		t.Fatalf("captured bytes changed: %q", got[0].Content)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(got[0].Content) != string(original) {
		t.Fatal("capture reopened mutable source")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "outside.md"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(home, []Reference{ref}); err == nil {
		t.Fatal("accepted selected symlink")
	}
}

func TestReferenceLimitsAndDeterministicFullDigest(t *testing.T) {
	if _, err := Encode([]Reference{{Source: SourceID, RelativePath: "../escape.md"}}); err == nil {
		t.Fatal("accepted traversal")
	}
	refs := make([]Reference, MaxEntries+1)
	for i := range refs {
		refs[i] = Reference{Source: SourceID, RelativePath: "x" + strings.Repeat("a", i) + ".md"}
	}
	if _, err := Encode(refs); err == nil {
		t.Fatal("accepted too many references")
	}
	ref := Reference{Source: SourceID, RelativePath: "nested/a.md"}
	name := DestinationName(ref)
	if len(name) != len("acs-instruction-")+64+len(".md") || name != DestinationName(ref) {
		t.Fatalf("noncanonical generated name %q", name)
	}
}

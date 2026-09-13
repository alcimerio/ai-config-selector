package instructions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverDepthBoundaryKeepsSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".acs", "instructions")
	deepest := filepath.Join(root, filepath.FromSlash(strings.Repeat("d/", MaxDepth-1)))
	if err := os.MkdirAll(deepest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepest, "valid.md"), []byte("valid"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		if err := os.Mkdir(filepath.Join(deepest, fmt.Sprintf("child-%02d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Reference.RelativePath != strings.Repeat("d/", MaxDepth-1)+"valid.md" {
		t.Fatalf("valid file at max depth omitted: %#v", got)
	}
}

func TestDecodeRejectsUnpairedSurrogatesAndPreservesSupplementaryCharacters(t *testing.T) {
	for _, raw := range []string{
		`[{"source":"acs-instructions","relativePath":"bad\ud800.md"}]`,
		`[{"source":"acs-instructions","relativePath":"bad\udc00.md"}]`,
	} {
		if refs, err := Decode(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted malformed identity %#v", refs)
		}
	}
	ref := Reference{Source: SourceID, RelativePath: "guide-😀.md"}
	raw, err := Encode([]Reference{ref})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil || len(got) != 1 || got[0] != ref {
		t.Fatalf("supplementary identity roundtrip = %#v, %v", got, err)
	}
}

func TestDiscoverTraversalBudgetIncludesIgnoredEntries(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".acs", "instructions")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("ignored-%04d.txt", i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Discover(home)
			if count == 4096 {
				if err != nil || len(got) != 0 {
					t.Fatalf("exact bound = %#v, %v", got, err)
				}
			} else if err == nil {
				t.Fatal("accepted traversal beyond bound")
			}
		})
	}
}

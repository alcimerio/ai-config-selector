package instructions

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func setupReview(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".acs", "instructions")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	return home, root
}

func TestReviewDiscoverSymlinkSkipsValidSibling(t *testing.T) {
	home, root := setupReview(t)
	if e := os.Symlink("absent", filepath.Join(root, "a-link")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "z-valid.md"), []byte("valid"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("absent", filepath.Join(root, "nested", "a-link")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "nested", "z-valid.md"), []byte("valid"), 0600); e != nil {
		t.Fatal(e)
	}
	got, e := Discover(home)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 2 {
		t.Fatalf("valid siblings omitted after symlink: %#v", got)
	}
}

func TestReviewCaptureDetectsConcurrentInPlaceWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture")
	if e := os.WriteFile(path, []byte("before"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	calls := 0
	_, e = captureVerified(f, func(file *os.File) ([]byte, error) {
		calls++
		data, e := io.ReadAll(file)
		if e == nil && calls == 1 {
			if e = os.WriteFile(path, []byte("after!"), 0600); e != nil {
				return nil, e
			}
		}
		return data, e
	})
	if e == nil {
		t.Fatal("accepted in-place mutation during capture")
	}
}

func TestReviewResolveAggregateBoundaryAndNonregular(t *testing.T) {
	home, root := setupReview(t)
	refs := make([]Reference, 0, 9)
	body := strings.Repeat("x", MaxFileBytes)
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("%02d.md", i)
		if e := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		refs = append(refs, Reference{Source: SourceID, RelativePath: name})
	}
	if _, e := Resolve(home, refs); e != nil {
		t.Fatalf("exact aggregate bound refused: %v", e)
	}
	if e := os.WriteFile(filepath.Join(root, "extra.md"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	refs = append(refs, Reference{Source: SourceID, RelativePath: "extra.md"})
	if _, e := Resolve(home, refs); e == nil {
		t.Fatal("accepted aggregate overflow")
	}
	if e := os.Mkdir(filepath.Join(root, "directory.md"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := Resolve(home, []Reference{{Source: SourceID, RelativePath: "directory.md"}}); e == nil {
		t.Fatal("accepted nonregular file")
	}
}

func TestReviewResolveRejectsWritableSourceDirectory(t *testing.T) {
	home, root := setupReview(t)
	if e := os.WriteFile(filepath.Join(root, "guide.md"), []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(root, 0777); e != nil {
		t.Fatal(e)
	}
	if _, e := Resolve(home, []Reference{{Source: SourceID, RelativePath: "guide.md"}}); e == nil {
		t.Fatal("accepted group/world writable source directory")
	}
}

func TestReviewGCDoesNotCloseUnrelatedReusedDescriptors(t *testing.T) {
	home, root := setupReview(t)
	if e := os.MkdirAll(filepath.Join(root, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "nested", "a.md"), []byte("valid"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := Resolve(home, []Reference{{Source: SourceID, RelativePath: "nested/a.md"}})
	if e != nil {
		t.Fatal(e)
	}
	files := []*os.File{}
	for i := 0; i < 20; i++ {
		f, e := os.Open(root)
		if e != nil {
			t.Fatal(e)
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
	}
	for i, f := range files {
		if _, e := f.Stat(); e != nil {
			t.Fatalf("unrelated descriptor %d closed after Resolve+GC: %v", i, e)
		}
	}
	runtime.KeepAlive(files)
}

func TestReviewIdentityRejectsNormalizationAndPrefixCollisions(t *testing.T) {
	for _, paths := range [][]string{{"A.md", "a.md"}, {"café.md", "cafe\u0301.md"}, {"a.md", "a.md/b.md"}} {
		refs := []Reference{}
		for _, p := range paths {
			refs = append(refs, Reference{Source: SourceID, RelativePath: p})
		}
		if e := ValidateSelection(refs); e == nil {
			t.Errorf("accepted collision %q", paths)
		}
	}
}

func TestReviewIdentityRejectsControlAndInvalidUTF8(t *testing.T) {
	for _, p := range []string{"nul\x00.md", "line\n.md", string([]byte{0xff}) + ".md"} {
		if e := ValidateSelection([]Reference{{Source: SourceID, RelativePath: p}}); e == nil {
			t.Errorf("accepted invalid identity %q", p)
		}
	}
}

func TestReviewReaderBoundsAndUnsafeModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"oversize", []byte(strings.Repeat("a", MaxFileBytes+1)), 0600}, {"nul", []byte("a\x00b"), 0600}, {"badutf8", []byte{255}, 0600}, {"writable", []byte("text"), 0666}} {
		t.Run(tc.name, func(t *testing.T) {
			home, root := setupReview(t)
			p := filepath.Join(root, "a.md")
			if e := os.WriteFile(p, tc.data, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(p, tc.mode); e != nil {
				t.Fatal(e)
			}
			if _, e := Resolve(home, []Reference{{Source: SourceID, RelativePath: "a.md"}}); e == nil {
				t.Fatal("accepted unsafe input")
			}
		})
	}
}

func TestReviewDiscoverMustNotFollowSourceAncestorLink(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if e := os.MkdirAll(filepath.Join(outside, "instructions"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(outside, "instructions", "external.md"), []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(home, ".acs")); e != nil {
		t.Fatal(e)
	}
	got, e := Discover(home)
	if e == nil && len(got) > 0 {
		t.Fatalf("catalog follows .acs link into external root: %#v", got)
	}
}

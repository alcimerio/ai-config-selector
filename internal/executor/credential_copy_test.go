package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyDevinCredentialPreservesRegularAndSymlinkSources(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "regular"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			fixture := t.TempDir()
			source := filepath.Join(fixture, "source")
			destination := filepath.Join(fixture, "session", "credential")
			if err := os.WriteFile(source, []byte("synthetic credential fixture"), 0o640); err != nil {
				t.Fatal(err)
			}
			if symlink {
				link := filepath.Join(fixture, "source-link")
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				source = link
			}
			if err := copyDevinCredentialIfPresent(source, destination); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(destination)
			if err != nil || string(contents) != "synthetic credential fixture" {
				t.Fatalf("unexpected synthetic credential copy: %v", err)
			}
			info, err := os.Lstat(destination)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("unexpected credential output type or mode: %v, %v", info, err)
			}
			if err := copyDevinCredentialIfPresent(source, destination); err == nil || err.Error() != "allowlisted credentials could not be copied safely" {
				t.Fatalf("exclusive copy error = %v", err)
			}
			contents, err = os.ReadFile(destination)
			if err != nil || string(contents) != "synthetic credential fixture" {
				t.Fatalf("existing credential changed: %v", err)
			}
		})
	}
}

func TestCopyDevinCredentialKeepsMissingFileSemantics(t *testing.T) {
	fixture := t.TempDir()
	missing := filepath.Join(fixture, "missing")
	link := filepath.Join(fixture, "dangling")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(fixture, "session")
	for _, source := range []string{missing, link} {
		if err := copyDevinCredentialIfPresent(source, filepath.Join(parent, "credential")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(parent); !os.IsNotExist(err) {
		t.Fatalf("created output for missing credential: %v", err)
	}
}

func TestCopyDevinCredentialSanitizesInspectionFailures(t *testing.T) {
	fixture := t.TempDir()
	parent := filepath.Join(fixture, "session")
	for _, test := range []struct{ source, message string }{
		{fixture, "allowlisted credentials path is not a regular file"},
		{filepath.Join(fixture, "private-fixture-"+strings.Repeat("x", 300)), "allowlisted credentials could not be inspected safely"},
	} {
		if err := copyDevinCredentialIfPresent(test.source, filepath.Join(parent, "credential")); err == nil || err.Error() != test.message {
			t.Fatalf("inspection error = %v, want %q", err, test.message)
		}
	}
	if _, err := os.Lstat(parent); !os.IsNotExist(err) {
		t.Fatalf("created output for invalid credential: %v", err)
	}
}

func TestCopyDevinCredentialSanitizesDestinationFailures(t *testing.T) {
	for _, kind := range []string{"file-parent", "symlink-parent"} {
		t.Run(kind, func(t *testing.T) {
			fixture := t.TempDir()
			source := filepath.Join(fixture, "source")
			parent := filepath.Join(fixture, "private-destination-fixture")
			other := filepath.Join(fixture, "other")
			if err := os.WriteFile(source, []byte("synthetic credential fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "file-parent" {
				if err := os.WriteFile(parent, []byte("existing fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(other, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, parent); err != nil {
					t.Fatal(err)
				}
			}
			if err := copyDevinCredentialIfPresent(source, filepath.Join(parent, "credential")); err == nil || err.Error() != "allowlisted credentials could not be copied safely" {
				t.Fatalf("destination error = %v, want sanitized copy failure", err)
			}
			if kind == "symlink-parent" {
				entries, err := os.ReadDir(other)
				if err != nil || len(entries) != 0 {
					t.Fatalf("wrote through destination directory symlink: %v", err)
				}
			}
		})
	}
}

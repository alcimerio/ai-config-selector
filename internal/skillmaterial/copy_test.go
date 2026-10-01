package skillmaterial

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyBundleRejectsDestinationDirectorySymlinks(t *testing.T) {
	for _, kind := range []string{"root", "root-trailing-separator", "nested"} {
		t.Run(kind, func(t *testing.T) {
			fixture := t.TempDir()
			source := filepath.Join(fixture, "source")
			destination := filepath.Join(fixture, "destination")
			other := filepath.Join(fixture, "other")
			writeFixture(t, filepath.Join(source, "nested", "fixture.txt"), "fixture", 0o600)
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			link := destination
			if kind == "nested" {
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
				link = filepath.Join(destination, "nested")
			}
			if err := os.Symlink(other, link); err != nil {
				t.Fatal(err)
			}
			if kind == "root-trailing-separator" {
				destination += string(filepath.Separator)
			}
			if err := CopyBundle(source, destination); err == nil {
				t.Fatal("accepted a destination directory symlink")
			}
			entries, err := os.ReadDir(other)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatal("wrote through a destination directory symlink")
			}
		})
	}
}

func TestCopyBundlePreservesSelectedRootAndDescendantLinks(t *testing.T) {
	fixture := t.TempDir()
	source := filepath.Join(fixture, "source")
	selected := filepath.Join(fixture, "selected")
	destination := filepath.Join(fixture, "destination")
	writeFixture(t, filepath.Join(source, "SKILL.md"), "# Fixture\n", 0o640)
	writeFixture(t, filepath.Join(source, "scripts", "run.sh"), "fixture only\n", 0o750)
	writeFixture(t, filepath.Join(fixture, "other", "fixture.txt"), "not selected\n", 0o600)
	links := map[string]string{
		"file-link":      "SKILL.md",
		"directory-link": "scripts",
		"dangling-link":  "missing",
		"relative-link":  "../other",
		"absolute-link":  filepath.Join(fixture, "other"),
		"long-link":      strings.Repeat("a", 300),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(source, selected); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CopyBundle(selected, destination); err != nil {
		t.Fatal(err)
	}
	for name, target := range links {
		copied := filepath.Join(destination, name)
		info, err := os.Lstat(copied)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s was not preserved as a symlink: %v", name, err)
		}
		if got, err := os.Readlink(copied); err != nil || got != target {
			t.Fatalf("%s target = %q, %v; want %q", name, got, err, target)
		}
	}
	assertFile(t, filepath.Join(destination, "SKILL.md"), "# Fixture\n", 0o640)
	assertFile(t, filepath.Join(destination, "scripts", "run.sh"), "fixture only\n", 0o750)
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("bundle directory mode was not preserved: %v, %v", info, err)
	}
}

func TestCopyBundlePreservesDirectoryModes(t *testing.T) {
	fixture := t.TempDir()
	source := filepath.Join(fixture, "source")
	destination := filepath.Join(fixture, "destination")
	writeFixture(t, filepath.Join(source, "nested", "fixture.txt"), "fixture", 0o400)
	for _, path := range []string{source, filepath.Join(source, "nested")} {
		if err := os.Chmod(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopyBundle(source, destination); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(destination, "nested", "fixture.txt"), "fixture", 0o400)
	for _, path := range []string{destination, filepath.Join(destination, "nested")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o750 {
			t.Fatalf("directory mode was not preserved: %v, %v", info, err)
		}
	}
}

func TestCopyFilePreservesCredentialSymlinkAndExclusiveCreation(t *testing.T) {
	fixture := t.TempDir()
	source := filepath.Join(fixture, "fixture-credential")
	link := filepath.Join(fixture, "credential-link")
	destination := filepath.Join(fixture, "destination", "credential")
	writeFixture(t, source, "synthetic credential", 0o640)
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(link, destination, 0o600); err != nil {
		t.Fatal(err)
	}
	assertFile(t, destination, "synthetic credential", 0o600)
	writeFixture(t, source, "replacement fixture", 0o640)
	if err := CopyFile(link, destination, 0o600); !os.IsExist(err) {
		t.Fatalf("second copy error = %v, want existing destination", err)
	}
	assertFile(t, destination, "synthetic credential", 0o600)
}

func TestCopyFileRejectsNonRegularInputBeforeCreatingDestination(t *testing.T) {
	fixture := t.TempDir()
	source := filepath.Join(fixture, "directory")
	parent := filepath.Join(fixture, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(source, filepath.Join(parent, "file"), 0o600); err == nil {
		t.Fatal("accepted a directory as file input")
	}
	if _, err := os.Lstat(parent); !os.IsNotExist(err) {
		t.Fatalf("created destination for non-regular input: %v", err)
	}
}

func TestCopyBundleRejectsNonDirectoryRoot(t *testing.T) {
	fixture := t.TempDir()
	source := filepath.Join(fixture, "file")
	destination := filepath.Join(fixture, "destination")
	writeFixture(t, source, "fixture", 0o600)
	if err := CopyBundle(source, destination); err == nil {
		t.Fatal("accepted a regular file as bundle root")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("created destination for invalid bundle root: %v", err)
	}
}

func TestCopyRegularFileRemovesIncompleteOutput(t *testing.T) {
	fixture := t.TempDir()
	parent, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	readFailure := errors.New("synthetic read failure")
	input := io.MultiReader(strings.NewReader("partial fixture"), failingReader{readFailure})
	if err := copyRegularFile(input, parent, "incomplete", 0o600); !errors.Is(err, readFailure) {
		t.Fatalf("copy error = %v, want synthetic read failure", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture, "incomplete")); !os.IsNotExist(err) {
		t.Fatalf("incomplete output remains: %v", err)
	}
}

func TestValidateInputRejectsDifferentOpenedObject(t *testing.T) {
	fixture := t.TempDir()
	wanted := filepath.Join(fixture, "wanted")
	writeFixture(t, wanted, "wanted fixture", 0o600)
	writeFixture(t, filepath.Join(fixture, "other"), "other fixture", 0o600)
	if err := os.Mkdir(filepath.Join(fixture, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(wanted)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"other", "directory"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.Open(filepath.Join(fixture, name))
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := validateInput(input, expected); err == nil {
				t.Fatal("accepted a descriptor for a different source object")
			}
		})
	}
}

func TestOpenAtDoesNotFollowChildLinks(t *testing.T) {
	fixture := t.TempDir()
	writeFixture(t, filepath.Join(fixture, "file"), "fixture", 0o600)
	if err := os.Mkdir(filepath.Join(fixture, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, target := range []string{"file", "directory", "missing"} {
		t.Run(target, func(t *testing.T) {
			name := target + "-link"
			if err := os.Symlink(target, filepath.Join(fixture, name)); err != nil {
				t.Fatal(err)
			}
			opened, err := openAt(parent, name, os.O_RDONLY, 0)
			if err == nil {
				opened.Close()
				t.Fatal("opened a child symlink")
			}
		})
	}
}

func TestDescriptorOperationsRequireSingleChildName(t *testing.T) {
	fixture := t.TempDir()
	parent, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, name := range []string{"", ".", "..", string(filepath.Separator), "nested/file", "../file", filepath.Join(fixture, "file")} {
		if opened, err := openAt(parent, name, os.O_RDONLY, 0); !errors.Is(err, os.ErrInvalid) {
			if opened != nil {
				opened.Close()
			}
			t.Fatalf("openAt(%q) = %v, want invalid name", name, err)
		}
		if err := mkdirAt(parent, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("mkdirAt(%q) = %v, want invalid name", name, err)
		}
		if _, err := readlinkAt(parent, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("readlinkAt(%q) = %v, want invalid name", name, err)
		}
		if err := symlinkAt(parent, "fixture", name); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("symlinkAt(%q) = %v, want invalid name", name, err)
		}
		if err := unlinkAt(parent, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("unlinkAt(%q) = %v, want invalid name", name, err)
		}
	}
}

func TestValidChildNameRejectsRoot(t *testing.T) {
	if validChildName(string(filepath.Separator)) {
		t.Fatal("accepted the filesystem root as a child name")
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func writeFixture(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != contents {
		t.Fatalf("unexpected fixture contents: %q, %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("unexpected file type or mode: %v, %v", info, err)
	}
}

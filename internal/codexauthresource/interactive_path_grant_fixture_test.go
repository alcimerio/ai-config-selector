package codexauthresource_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type nativeCodexPathGrantFixture struct {
	readWriteFile, readWriteSibling, renamedFile string
	readWriteDirectory, readOnlyFile             string
	readOnlyParent, writableChild                string
	descendantReady                              string
}

func prepareNativeCodexPathGrantFixture(t *testing.T, home string) nativeCodexPathGrantFixture {
	t.Helper()
	root := filepath.Join(home, "path-grant-fixture")
	fixture := nativeCodexPathGrantFixture{
		readWriteFile:      filepath.Join(root, "exact-file"),
		readWriteSibling:   filepath.Join(root, "exact-file-sibling"),
		renamedFile:        filepath.Join(root, "renamed-file"),
		readWriteDirectory: filepath.Join(root, "writable-directory"),
		readOnlyFile:       filepath.Join(root, "read-only-file"),
		readOnlyParent:     filepath.Join(root, "read-only-parent"),
		writableChild:      filepath.Join(root, "read-only-parent", "writable-child"),
	}
	fixture.descendantReady = filepath.Join(fixture.readWriteDirectory, "descendant-ready")
	for _, directory := range []string{root, fixture.readWriteDirectory, fixture.writableChild} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		fixture.readWriteFile:                                "exact-before\n",
		filepath.Join(fixture.readWriteDirectory, "source"):  "directory-source\n",
		fixture.readOnlyFile:                                 "read-only-original\n",
		filepath.Join(fixture.readOnlyParent, "parent-file"): "parent-original\n",
		filepath.Join(fixture.writableChild, "child-file"):   "child-original\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func nativeShellArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func nativeCodexPathGrantCommand(fixture nativeCodexPathGrantFixture) string {
	q := nativeShellArgument
	parentDenied := filepath.Join(fixture.readOnlyParent, "parent-denied")
	parentDirectoryWrite := filepath.Join(fixture.readWriteDirectory, "parent-write")
	parentChildWrite := filepath.Join(fixture.writableChild, "parent-child-write")
	childDirectoryWrite := filepath.Join(fixture.readWriteDirectory, "child-write")
	childChildWrite := filepath.Join(fixture.writableChild, "child-child-write")
	childSibling := fixture.readWriteFile + "-child-sibling"
	child := fmt.Sprintf(`if IFS= read -r child_value < %s 2>/dev/null; then printf 'child-exact-read-ok\n'; else printf 'child-exact-read-bad\n'; fi
if printf 'child-exact\n' > %s 2>/dev/null; then printf 'child-exact-write-ok\n'; else printf 'child-exact-write-bad\n'; fi
if printf 'bad\n' > %s 2>/dev/null; then printf 'child-exact-sibling-write-bad\n'; else printf 'child-exact-sibling-write-denied\n'; fi
if IFS= read -r child_value < %s 2>/dev/null; then printf 'child-directory-read-ok\n'; else printf 'child-directory-read-bad\n'; fi
if printf 'child-directory\n' > %s 2>/dev/null; then printf 'child-directory-write-ok\n'; else printf 'child-directory-write-bad\n'; fi
if IFS= read -r child_value < %s 2>/dev/null; then printf 'child-read-only-read-ok\n'; else printf 'child-read-only-read-bad\n'; fi
if printf 'bad\n' > %s 2>/dev/null; then printf 'child-read-only-write-bad\n'; else printf 'child-read-only-write-denied\n'; fi
if IFS= read -r child_value < %s 2>/dev/null; then printf 'child-overlap-read-ok\n'; else printf 'child-overlap-read-bad\n'; fi
if printf 'child-overlap\n' > %s 2>/dev/null; then printf 'child-overlap-write-ok\n'; else printf 'child-overlap-write-bad\n'; fi`,
		q(fixture.readWriteFile), q(fixture.readWriteFile), q(childSibling),
		q(filepath.Join(fixture.readWriteDirectory, "source")), q(childDirectoryWrite),
		q(fixture.readOnlyFile), q(fixture.readOnlyFile),
		q(filepath.Join(fixture.writableChild, "child-file")), q(childChildWrite))
	return fmt.Sprintf(`printf 'codex-native-tool-output\n'
if IFS= read -r parent_value < %s 2>/dev/null; then printf 'parent-exact-read-ok\n'; else printf 'parent-exact-read-bad\n'; fi
if printf 'parent-exact\n' > %s 2>/dev/null; then printf 'parent-exact-write-ok\n'; else printf 'parent-exact-write-bad\n'; fi
if printf 'bad\n' > %s 2>/dev/null; then printf 'parent-exact-sibling-write-bad\n'; else printf 'parent-exact-sibling-write-denied\n'; fi
if IFS= read -r parent_value < %s 2>/dev/null; then printf 'parent-directory-read-ok\n'; else printf 'parent-directory-read-bad\n'; fi
if printf 'parent-directory\n' > %s 2>/dev/null; then printf 'parent-directory-write-ok\n'; else printf 'parent-directory-write-bad\n'; fi
if IFS= read -r parent_value < %s 2>/dev/null; then printf 'parent-read-only-read-ok\n'; else printf 'parent-read-only-read-bad\n'; fi
if printf 'bad\n' > %s 2>/dev/null; then printf 'parent-read-only-write-bad\n'; else printf 'parent-read-only-write-denied\n'; fi
if IFS= read -r parent_value < %s 2>/dev/null && IFS= read -r parent_value < %s 2>/dev/null; then printf 'parent-overlap-read-ok\n'; else printf 'parent-overlap-read-bad\n'; fi
if printf 'bad\n' > %s 2>/dev/null; then printf 'parent-overlap-parent-write-bad\n'; else printf 'parent-overlap-parent-write-denied\n'; fi
if printf 'parent-overlap\n' > %s 2>/dev/null; then printf 'parent-overlap-child-write-ok\n'; else printf 'parent-overlap-child-write-bad\n'; fi
/bin/sh -c %s
if mv %s %s 2>/dev/null; then printf 'parent-exact-rename-bad\n'; else printf 'parent-exact-rename-denied\n'; fi`,
		q(fixture.readWriteFile), q(fixture.readWriteFile), q(fixture.readWriteSibling),
		q(filepath.Join(fixture.readWriteDirectory, "source")), q(parentDirectoryWrite),
		q(fixture.readOnlyFile), q(fixture.readOnlyFile),
		q(filepath.Join(fixture.readOnlyParent, "parent-file")), q(filepath.Join(fixture.writableChild, "child-file")),
		q(parentDenied), q(parentChildWrite), q(child), q(fixture.readWriteFile), q(fixture.renamedFile))
}

func assertNativeCodexPathGrantEffects(t *testing.T, fixture nativeCodexPathGrantFixture) {
	t.Helper()
	assertContents := func(path, want string) {
		t.Helper()
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Fatalf("path-grant effect %s=%q err=%v, want %q", filepath.Base(path), contents, err, want)
		}
	}
	assertMissing := func(path string) {
		t.Helper()
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("denied path-grant effect exists at %s: %v", filepath.Base(path), err)
		}
	}
	assertContents(fixture.readWriteFile, "child-exact\n")
	assertMissing(fixture.readWriteSibling)
	assertMissing(fixture.readWriteFile + "-child-sibling")
	assertMissing(fixture.renamedFile)
	assertContents(filepath.Join(fixture.readWriteDirectory, "parent-write"), "parent-directory\n")
	assertContents(filepath.Join(fixture.readWriteDirectory, "child-write"), "child-directory\n")
	assertContents(fixture.readOnlyFile, "read-only-original\n")
	assertContents(filepath.Join(fixture.readOnlyParent, "parent-file"), "parent-original\n")
	assertMissing(filepath.Join(fixture.readOnlyParent, "parent-denied"))
	assertContents(filepath.Join(fixture.writableChild, "parent-child-write"), "parent-overlap\n")
	assertContents(filepath.Join(fixture.writableChild, "child-child-write"), "child-overlap\n")
}

func TestNativeCodexPathGrantCommandExecutesPositiveParentAndChildOperations(t *testing.T) {
	fixture := prepareNativeCodexPathGrantFixture(t, t.TempDir())
	command := nativeCodexPathGrantCommand(fixture)
	if output, err := exec.Command("/bin/sh", "-n", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("path-grant shell syntax: %v; output=%q", err, output)
	}
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("uncontained path-grant diagnostic: %v; output=%q", err, output)
	}
	for _, witness := range []string{
		"parent-exact-read-ok", "parent-exact-write-ok", "parent-directory-read-ok", "parent-directory-write-ok",
		"parent-read-only-read-ok", "parent-overlap-read-ok", "parent-overlap-child-write-ok",
		"child-exact-read-ok", "child-exact-write-ok", "child-directory-read-ok", "child-directory-write-ok",
		"child-read-only-read-ok", "child-overlap-read-ok", "child-overlap-write-ok",
	} {
		if !strings.Contains(string(output), witness+"\n") {
			t.Fatalf("uncontained path-grant diagnostic omitted %q: output=%q", witness, output)
		}
	}
	// This source-host diagnostic intentionally runs without Seatbelt. These
	// branches must therefore report successful forbidden operations; only the
	// installed-candidate native gate may establish the denial witnesses.
	for _, witness := range []string{
		"parent-exact-sibling-write-bad", "parent-read-only-write-bad", "parent-overlap-parent-write-bad",
		"child-exact-sibling-write-bad", "child-read-only-write-bad", "parent-exact-rename-bad",
	} {
		if !strings.Contains(string(output), witness+"\n") {
			t.Fatalf("uncontained conditional diagnostic omitted %q: output=%q", witness, output)
		}
	}
	for path, want := range map[string]string{
		fixture.renamedFile: "child-exact\n",
		filepath.Join(fixture.readWriteDirectory, "parent-write"):  "parent-directory\n",
		filepath.Join(fixture.readWriteDirectory, "child-write"):   "child-directory\n",
		filepath.Join(fixture.writableChild, "parent-child-write"): "parent-overlap\n",
		filepath.Join(fixture.writableChild, "child-child-write"):  "child-overlap\n",
	} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("uncontained positive effect %s=%q err=%v, want %q", filepath.Base(path), contents, readErr, want)
		}
	}
}

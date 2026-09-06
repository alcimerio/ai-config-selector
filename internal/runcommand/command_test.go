package runcommand

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePreservesLiteralArgumentsAndIgnoresHostPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	command, err := Resolve(t.TempDir(), []string{"sh", "space value", "", "--", "*.go", "$HOME"})
	if err != nil {
		t.Fatal(err)
	}
	executable, arguments, err := command.Revalidate(command.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(executable) || command.Form() != BareName || filepath.Dir(executable) == os.Getenv("PATH") {
		t.Fatalf("resolved executable = %q", executable)
	}
	want := []string{"space value", "", "--", "*.go", "$HOME"}
	for index := range want {
		if arguments[index] != want[index] {
			t.Fatalf("argument %d = %q, want %q", index, arguments[index], want[index])
		}
	}
}

func TestWorkspaceRelativeExecutableMustRemainContainedAndUnchanged(t *testing.T) {
	workspace := t.TempDir()
	tool := filepath.Join(workspace, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command, err := Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(workspace, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 123\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, tool); err != nil {
		t.Fatal(err)
	}
	if _, _, err := command.Revalidate(workspace); err == nil {
		t.Fatal("revalidation accepted a replaced executable")
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(workspace, []string{"./escape"}); err == nil {
		t.Fatal("workspace-relative symlink escaped the workspace")
	}
}

func TestValidateSyntaxRejectsAmbiguousExecutableFormsAndNUL(t *testing.T) {
	for _, argv := range [][]string{nil, {""}, {"--"}, {"sub/tool"}, {"../tool"}, {"tool", "bad\x00value"}} {
		if err := ValidateSyntax(argv); err == nil {
			t.Fatalf("accepted argv %#v", argv)
		}
	}
}

func FuzzValidateSyntaxNeverPanics(f *testing.F) {
	f.Add("tool", "value")
	f.Add("./tool", "")
	f.Fuzz(func(t *testing.T, executable, argument string) {
		_ = ValidateSyntax([]string{executable, argument})
	})
}

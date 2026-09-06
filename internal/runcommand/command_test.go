package runcommand

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestResolveRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	workspace := t.TempDir()
	tool := filepath.Join(workspace, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(tool, 0o700); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := Resolve(workspace, []string{"./tool"})
		result <- err
	}()
	if err := awaitSpecialFileRejection(t, tool, result); err == nil {
		t.Fatal("Resolve accepted an executable-mode FIFO")
	}
}

func TestRevalidateRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	workspace := t.TempDir()
	tool := filepath.Join(workspace, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command, err := Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(tool, 0o700); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, err := command.Revalidate(workspace)
		result <- err
	}()
	if err := awaitSpecialFileRejection(t, tool, result); err == nil {
		t.Fatal("Revalidate accepted an executable-mode FIFO replacement")
	}
}

func awaitSpecialFileRejection(t *testing.T, fifo string, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(250 * time.Millisecond):
		writer, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("unblock FIFO reader: %v", err)
		}
		_ = unix.Close(writer)
		select {
		case <-result:
			t.Fatal("special-file resolution blocked while opening a FIFO")
		case <-time.After(2 * time.Second):
			t.Fatal("special-file resolution remained blocked after FIFO cleanup")
		}
	}
	return nil
}

func TestRevalidateRejectsWorkspaceReplacementAtSamePath(t *testing.T) {
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	command, err := Resolve(workspace, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(workspace, filepath.Join(parent, "old-workspace")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := command.Revalidate(workspace); err == nil {
		t.Fatal("revalidation accepted a different workspace at the original path")
	}
}

func TestResolveAndRevalidatePreserveExecutableSymlinks(t *testing.T) {
	workspace := t.TempDir()
	target := filepath.Join(workspace, "target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(workspace, "tool")); err != nil {
		t.Fatal(err)
	}
	command, err := Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	if executable, _, err := command.Revalidate(workspace); err != nil || executable != command.executable {
		t.Fatalf("symlink revalidation = (%q, %v), want canonical target %q", executable, err, command.executable)
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

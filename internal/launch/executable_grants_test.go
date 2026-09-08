package launch

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutableFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
}

func withExecutableSearchPath(t *testing.T, roots ...string) {
	t.Helper()
	previous := executableSearchPath
	executableSearchPath = filepath.Join(roots...)
	if len(roots) > 1 {
		executableSearchPath = roots[0]
		for _, root := range roots[1:] {
			executableSearchPath += string(os.PathListSeparator) + root
		}
	}
	t.Cleanup(func() { executableSearchPath = previous })
}

func TestExecutableGrantFixedSearchPrecedenceRevalidated(t *testing.T) {
	root := t.TempDir()
	first, second, third := filepath.Join(root, "first"), filepath.Join(root, "second"), filepath.Join(root, "third")
	withExecutableSearchPath(t, first, second, third)
	workspace, sessions := filepath.Join(root, "workspace"), filepath.Join(root, "sessions")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutableFixture(t, filepath.Join(second, "tool"), "second")
	writeExecutableFixture(t, filepath.Join(third, "tool"), "third1")
	grants, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "tool", ReferenceKind: ExecutableReferenceFixedSearchName, Name: "tool"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err != nil {
		t.Fatalf("unchanged search: %v", err)
	}
	writeExecutableFixture(t, filepath.Join(third, "tool"), "third2")
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err != nil {
		t.Fatalf("lower-priority change affected selected executable: %v", err)
	}

	writeExecutableFixture(t, filepath.Join(first, "tool"), "first")
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err == nil {
		t.Fatal("accepted newly appearing higher-priority executable")
	}
	if err := os.Remove(filepath.Join(first, "tool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(second, "tool"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err == nil {
		t.Fatal("accepted selected executable becoming non-executable")
	}
}

func TestExecutableGrantRejectsSpecialFilesAndContentReplacement(t *testing.T) {
	root := t.TempDir()
	workspace, sessions := filepath.Join(root, "workspace"), filepath.Join(root, "sessions")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(workspace, "tool")
	writeExecutableFixture(t, regular, "first")
	intent := []ExecutableGrantIntent{{ID: "tool", ReferenceKind: ExecutableReferenceWorkspaceRelative, Path: "tool"}}
	grants, err := ResolveExecutableGrants(intent, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(regular)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutableFixture(t, regular, "other")
	if err := os.Chtimes(regular, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(regular)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("fixture changed identity or metadata: before=%#v after=%#v", before, after)
	}
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err == nil {
		t.Fatal("accepted same-size executable content replacement")
	}

	for name, prepare := range map[string]func(string) error{
		"directory": func(path string) error { return os.Mkdir(path, 0o755) },
		"fifo":      func(path string) error { return syscallMkfifo(path, 0o755) },
		"socket": func(path string) error {
			listener, err := net.Listen("unix", path)
			if err == nil {
				t.Cleanup(func() { _ = listener.Close() })
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := filepath.Join(workspace, name)
			if err := prepare(candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: name, ReferenceKind: ExecutableReferenceWorkspaceRelative, Path: name}}, workspace, sessions); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestExecutableGrantMutationIsRefusedAtCheckAndPrepareFences(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	sessionRoot := filepath.Join(sessions, "operation")
	sessionHome := filepath.Join(sessionRoot, "home")
	temporary := filepath.Join(sessionRoot, "tmp")
	primary := filepath.Join(root, "primary")
	tool := filepath.Join(workspace, "bin", "helper")
	for _, directory := range []string{workspace, sessionHome, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutableFixture(t, primary, "primary")
	writeExecutableFixture(t, tool, "helper-v1")
	grants, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "helper", ReferenceKind: ExecutableReferenceWorkspaceRelative, Path: "bin/helper"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	check := SandboxCheck{Workspace: workspace, WorkspaceAccess: WorkspaceAccessReadOnly, SessionsDirectory: sessions, Executable: primary, ExecutableGrants: grants}
	if _, err := validateSandboxCheck(check); err != nil {
		t.Fatalf("unchanged Check rejected: %v", err)
	}
	process := ProcessRequest{Workspace: workspace, WorkspaceAccess: WorkspaceAccessReadOnly, SessionsDirectory: sessions, SessionDirectory: sessionRoot, SessionHome: sessionHome, TemporaryDirectory: temporary, Executable: primary, ExecutableGrants: grants}
	if _, err := validateProcessRequest(process); err != nil {
		t.Fatalf("unchanged Prepare rejected: %v", err)
	}
	before, err := os.Stat(tool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("helper-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tool, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSandboxCheck(check); err == nil || !strings.Contains(err.Error(), string(SandboxUnsafePath)) {
		t.Fatalf("mutated executable reached Check: %v", err)
	}
	if _, err := validateProcessRequest(process); err == nil || !strings.Contains(err.Error(), string(SandboxUnsafePath)) {
		t.Fatalf("mutated executable reached Prepare: %v", err)
	}
}

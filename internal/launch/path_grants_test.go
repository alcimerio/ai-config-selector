package launch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFilesystemGrantResolutionReductionAndIdentityRevalidation(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(filepath.Join(workspace, "data", "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(workspace, "data", "child", "value")
	if err := os.WriteFile(file, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	intents := []PathGrantIntent{
		{ID: "parent", Access: PathAccessReadOnly, Type: PathTypeDirectory, ReferenceKind: PathReferenceWorkspaceRelative, Path: "data"},
		{ID: "child", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "data/child/value"},
		{ID: "write", Access: PathAccessReadWrite, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "data/child/value"},
	}
	grants, err := ResolveFilesystemGrants(intents, workspace, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 3 {
		t.Fatalf("unexpected reduction: %#v", grants)
	}
	effective := map[string]bool{}
	for _, grant := range grants {
		effective[grant.ID] = grant.effective
	}
	if effective["parent"] || !effective["write"] || effective["child"] {
		t.Fatalf("unexpected reduction: %#v", grants)
	}
	if _, err := revalidateFilesystemGrants(grants, workspace, sessions); err != nil {
		t.Fatal(err)
	}
	// Directory link counts are volatile traversal metadata, not identity.
	// Creating an unrelated directory beside the selected tree must not make a
	// stable selection look replaced.
	siblingDirectory := filepath.Join(root, "unrelated-sibling-directory")
	if err := os.Mkdir(siblingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemGrants(grants, workspace, sessions); err != nil {
		t.Fatalf("unrelated sibling directory changed traversal identity: %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := os.WriteFile(file, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemGrants(grants, workspace, sessions); err == nil {
		t.Fatal("content identity drift accepted")
	}

	grants, err = ResolveFilesystemGrants(intents, workspace, sessions, WorkspaceAccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if grant.effective {
			t.Fatalf("writable workspace did not dominate %#v", grant)
		}
	}
}

type workspaceAnchorFixture struct {
	root, first, second, link, sessions, selected string
	grants                                        []FilesystemGrant
	workspaceAccess                               WorkspaceAccess
}

func newWorkspaceAnchorFixture(t *testing.T, effective bool) workspaceAnchorFixture {
	t.Helper()
	root := t.TempDir()
	fixture := workspaceAnchorFixture{
		root: root, first: filepath.Join(root, "first"), second: filepath.Join(root, "second"),
		link: filepath.Join(root, "workspace"), sessions: filepath.Join(root, "sessions"),
		workspaceAccess: WorkspaceAccessReadWrite,
	}
	if effective {
		fixture.workspaceAccess = WorkspaceAccessReadOnly
	}
	for _, directory := range []string{fixture.first, fixture.second} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "selected"), []byte("stable\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(fixture.first, fixture.link); err != nil {
		t.Fatal(err)
	}
	fixture.selected = filepath.Join(fixture.first, "selected")
	var err error
	fixture.grants, err = ResolveFilesystemGrants([]PathGrantIntent{{
		ID: "selected", Access: PathAccessReadWrite, Type: PathTypeFile,
		ReferenceKind: PathReferenceWorkspaceRelative, Path: "selected",
	}}, fixture.link, fixture.sessions, fixture.workspaceAccess)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.grants) != 1 || fixture.grants[0].effective != effective || fixture.grants[0].path != fixture.selected {
		t.Fatalf("resolved workspace-relative grants = %#v", fixture.grants)
	}
	return fixture
}

func (fixture workspaceAnchorFixture) mutateWorkspace(t *testing.T, mutation string) {
	t.Helper()
	if mutation == "unchanged" {
		return
	}
	if err := os.Rename(fixture.link, filepath.Join(fixture.root, "retired-workspace-link")); err != nil {
		t.Fatal(err)
	}
	target := fixture.first
	if mutation == "retargeted" {
		target = fixture.second
	}
	if err := os.Symlink(target, fixture.link); err != nil {
		t.Fatal(err)
	}
}

func (fixture workspaceAnchorFixture) sandbox(t *testing.T) (*nativeProcessSandbox, *capturingBackend) {
	t.Helper()
	backend := &capturingBackend{}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
		map[string]sandboxBackend{"darwin": backend},
	)
	sandbox.environ = func() []string { return []string{"TERM=xterm-256color", "LANG=C"} }
	return sandbox, backend
}

func (fixture workspaceAnchorFixture) checkRequest() SandboxCheck {
	return SandboxCheck{
		Workspace: fixture.link, WorkspaceAccess: fixture.workspaceAccess,
		SessionsDirectory: fixture.sessions, Executable: "/bin/sh", FilesystemGrants: fixture.grants,
	}
}

func TestFilesystemGrantWorkspaceAnchorRevalidatedAtCheck(t *testing.T) {
	for _, effective := range []bool{true, false} {
		intent := "dominated"
		if effective {
			intent = "effective"
		}
		for _, mutation := range []string{"unchanged", "replaced", "retargeted"} {
			t.Run(intent+"/"+mutation, func(t *testing.T) {
				fixture := newWorkspaceAnchorFixture(t, effective)
				fixture.mutateWorkspace(t, mutation)
				sandbox, _ := fixture.sandbox(t)
				err := sandbox.Check(context.Background(), fixture.checkRequest())
				if mutation == "unchanged" {
					if err != nil {
						t.Fatalf("unchanged workspace anchor rejected at Check: %v", err)
					}
					return
				}
				assertSandboxCategory(t, err, SandboxUnsafePath)
			})
		}
	}
}

func TestFilesystemGrantWorkspaceAnchorRevalidatedAfterSessionAtPrepare(t *testing.T) {
	for _, effective := range []bool{true, false} {
		intent := "dominated"
		if effective {
			intent = "effective"
		}
		for _, mutation := range []string{"unchanged", "replaced", "retargeted"} {
			t.Run(intent+"/"+mutation, func(t *testing.T) {
				fixture := newWorkspaceAnchorFixture(t, effective)
				sandbox, backend := fixture.sandbox(t)
				if err := sandbox.Check(context.Background(), fixture.checkRequest()); err != nil {
					t.Fatalf("initial Check rejected workspace anchor: %v", err)
				}
				session := filepath.Join(fixture.sessions, "session-one")
				home, temporary := filepath.Join(session, "home"), filepath.Join(session, "tmp")
				for _, directory := range []string{home, temporary} {
					if err := os.MkdirAll(directory, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				fixture.mutateWorkspace(t, mutation)
				process, err := sandbox.Prepare(context.Background(), ProcessRequest{
					Workspace: fixture.link, WorkspaceAccess: fixture.workspaceAccess,
					SessionsDirectory: fixture.sessions, SessionDirectory: session,
					SessionHome: home, TemporaryDirectory: temporary, Executable: "/bin/sh",
					FilesystemGrants: fixture.grants,
				})
				if mutation == "unchanged" {
					if err != nil || process == nil || backend.request.workspace != fixture.first {
						t.Fatalf("unchanged workspace anchor Prepare = process %T backend workspace %q err %v", process, backend.request.workspace, err)
					}
					return
				}
				if process != nil {
					t.Fatalf("changed workspace anchor returned process %T", process)
				}
				assertSandboxCategory(t, err, SandboxUnsafePath)
				if backend.request.workspace != "" {
					t.Fatal("changed workspace anchor reached backend preparation")
				}
				if _, statErr := os.Stat(session); statErr != nil {
					t.Fatalf("anchor validation changed caller-owned Session: %v", statErr)
				}
			})
		}
	}
}

func TestFilesystemGrantRejectsSpecialFilesEscapesHardlinksAndProtectedAliases(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "escape", Access: PathAccessReadOnly, Type: PathTypeDirectory, ReferenceKind: PathReferenceWorkspaceRelative, Path: "escape"}}, workspace, sessions, WorkspaceAccessReadOnly); err == nil {
		t.Fatal("symlink escape accepted")
	}

	fifo := filepath.Join(workspace, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "fifo", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "fifo"}}, workspace, sessions, WorkspaceAccessReadOnly); err == nil {
		t.Fatal("FIFO accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("FIFO inspection blocked")
	}

	original := filepath.Join(root, "protected-file")
	alias := filepath.Join(workspace, "alias")
	if err := os.WriteFile(original, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Fatal(err)
	}
	writeAlias := []PathGrantIntent{{ID: "alias", Access: PathAccessReadWrite, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "alias"}}
	if _, err := ResolveFilesystemGrants(writeAlias, workspace, sessions, WorkspaceAccessReadOnly); err == nil {
		t.Fatal("writable hard link accepted")
	}
	readAlias := []PathGrantIntent{{ID: "alias", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "alias"}}
	control := filepath.Join(workspace, "ordinary")
	if err := os.WriteFile(control, []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "ordinary", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "ordinary"}}, workspace, sessions, WorkspaceAccessReadOnly, []string{original}); err != nil {
		t.Fatalf("ordinary control rejected: %v", err)
	}
	if _, err := ResolveFilesystemGrants(readAlias, workspace, sessions, WorkspaceAccessReadOnly, []string{original}); err == nil {
		t.Fatal("protected hard-link alias accepted")
	}
}

func TestFilesystemGrantRejectsLogicalSymlinkRetarget(t *testing.T) {
	root := t.TempDir()
	workspace, sessions := filepath.Join(root, "workspace"), filepath.Join(root, "sessions")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	first, second, link := filepath.Join(workspace, "first"), filepath.Join(workspace, "second"), filepath.Join(workspace, "link")
	if err := os.WriteFile(first, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	grants, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "linked", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "link"}}, workspace, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemGrants(grants, workspace, sessions); err == nil {
		t.Fatal("logical symlink retarget accepted")
	}
}

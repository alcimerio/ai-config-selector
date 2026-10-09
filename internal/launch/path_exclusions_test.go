package launch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemExclusionsCaptureAbsentLeafAnchorsAndDrift(t *testing.T) {
	root := filesystemGrantTestRoot(t)
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(filepath.Join(workspace, "container", "skills"), 0700); err != nil {
		t.Fatal(err)
	}
	intent := PathExclusionIntent{ID: "repo-skills", Type: PathTypeDirectory, ReferenceKind: PathReferenceWorkspaceRelative, Path: "container/skills"}
	exclusions, err := ResolveFilesystemExclusions([]PathExclusionIntent{intent}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemExclusions(exclusions, workspace, sessions); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExclusionSources(exclusions, []string{filepath.Join(workspace, "container")}); err == nil {
		t.Fatal("bundle ancestor accepted")
	}
	if err := os.Rename(filepath.Join(workspace, "container"), filepath.Join(workspace, "moved")); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemExclusions(exclusions, workspace, sessions); err == nil {
		t.Fatal("ancestor drift accepted")
	}
	intent.Path = "moved/missing"
	intent.Type = PathTypeFile
	absent, err := ResolveFilesystemExclusions([]PathExclusionIntent{intent}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemExclusions(absent, workspace, sessions); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "moved", "missing"), []byte("late"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateFilesystemExclusions(absent, workspace, sessions); err == nil {
		t.Fatal("absent identity drift accepted")
	}
	intent.Path = "moved/missing/below-file"
	if _, err := ResolveFilesystemExclusions([]PathExclusionIntent{intent}, workspace, sessions); err == nil {
		t.Fatal("exclusion below an existing file accepted")
	}
	intent.Path = "moved/skills"
	intent.Type = PathTypeFile
	if _, err := ResolveFilesystemExclusions([]PathExclusionIntent{intent}, workspace, sessions); err == nil {
		t.Fatal("type mismatch accepted")
	}
}

func TestFilesystemExclusionsRejectRuntimeAndSelectedGrantConflicts(t *testing.T) {
	root := filesystemGrantTestRoot(t)
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(filepath.Join(workspace, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(workspace, "private", "tool")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	exclusions, err := ResolveFilesystemExclusions([]PathExclusionIntent{{ID: "private", Type: PathTypeDirectory, ReferenceKind: PathReferenceWorkspaceRelative, Path: "private"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	check := SandboxCheck{Workspace: workspace, SessionsDirectory: sessions, Executable: file, FilesystemExclusions: exclusions}
	_, err = validateSandboxCheck(check)
	if err == nil || !strings.Contains(err.Error(), `excluded path "private"`) {
		t.Fatalf("runtime conflict: %v", err)
	}
	grants, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "child", Type: PathTypeFile, Access: PathAccessReadOnly, ReferenceKind: PathReferenceWorkspaceRelative, Path: "private/tool"}}, workspace, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	check.Executable = "/bin/sh"
	check.FilesystemGrants = grants
	if _, err := validateSandboxCheck(check); err == nil {
		t.Fatal("selected descendant grant accepted")
	}
	check.FilesystemGrants = nil
	check.RuntimeInputs = []string{file}
	if _, err := validateSandboxCheck(check); err == nil || !strings.Contains(err.Error(), `excluded path "private"`) {
		t.Fatalf("required runtime input conflict: %v", err)
	}
	check.RuntimeInputs = nil
	grants, err = ResolveFilesystemGrants([]PathGrantIntent{{ID: "parent", Type: PathTypeDirectory, Access: PathAccessReadWrite, ReferenceKind: PathReferenceLocalAbsolute, Path: workspace}}, workspace, sessions, WorkspaceAccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	check.FilesystemGrants = grants
	check.WorkspaceAccess = WorkspaceAccessReadWrite
	if _, err := validateSandboxCheck(check); err != nil {
		t.Fatalf("broad grant rejected: %v", err)
	}
}

func TestFilesystemExclusionsRevalidateWorkspaceAtCheckPrepareAndStart(t *testing.T) {
	for _, phase := range []string{"check", "prepare", "start"} {
		for _, mutation := range []string{"unchanged", "replaced", "retargeted"} {
			t.Run(phase+"/"+mutation, func(t *testing.T) {
				fixture := newWorkspaceAnchorFixture(t, false)
				exclusions, err := ResolveFilesystemExclusions([]PathExclusionIntent{{ID: "selected", Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "selected"}}, fixture.link, fixture.sessions)
				if err != nil {
					t.Fatal(err)
				}
				sandbox, backend := fixture.sandbox(t)
				child := &preparedProtectionProcess{cleanupDone: make(chan struct{})}
				backend.process = child
				check := fixture.checkRequest()
				check.FilesystemGrants = nil
				check.FilesystemExclusions = exclusions
				if phase == "check" {
					fixture.mutateWorkspace(t, mutation)
				}
				err = sandbox.Check(context.Background(), check)
				if phase == "check" {
					if mutation == "unchanged" {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						assertSandboxCategory(t, err, SandboxUnsafePath)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				session := filepath.Join(fixture.sessions, "session-one")
				home, tmp := filepath.Join(session, "home"), filepath.Join(session, "tmp")
				for _, dir := range []string{home, tmp} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "prepare" {
					fixture.mutateWorkspace(t, mutation)
				}
				process, err := sandbox.Prepare(context.Background(), ProcessRequest{Workspace: fixture.link, WorkspaceAccess: fixture.workspaceAccess, SessionsDirectory: fixture.sessions, SessionDirectory: session, SessionHome: home, TemporaryDirectory: tmp, Executable: "/bin/sh", FilesystemExclusions: exclusions})
				if phase == "prepare" {
					if mutation == "unchanged" {
						if err != nil || process == nil {
							t.Fatalf("prepare=%v", err)
						}
					} else {
						assertSandboxCategory(t, err, SandboxUnsafePath)
						if process != nil || backend.request.workspace != "" {
							t.Fatal("drift reached backend")
						}
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				fixture.mutateWorkspace(t, mutation)
				err = process.Start()
				if mutation == "unchanged" {
					if err != nil || !child.started {
						t.Fatalf("start=%v", err)
					}
				} else {
					assertSandboxCategory(t, err, SandboxUnsafePath)
					if child.started || child.aborts != 1 {
						t.Fatal("drift reached Start or omitted abort")
					}
				}
			})
		}
	}
}

func TestFilesystemExclusionsAnchorMissingAncestorsAtNearestExistingDirectory(t *testing.T) {
	root := filesystemGrantTestRoot(t)
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	intent := PathExclusionIntent{ID: "build-secrets", Type: PathTypeDirectory, ReferenceKind: PathReferenceWorkspaceRelative, Path: "build/out/secrets"}
	exclusions, err := ResolveFilesystemExclusions([]PathExclusionIntent{intent}, workspace, sessions)
	if err != nil {
		t.Fatalf("missing ancestors blocked the exclusion: %v", err)
	}
	if len(exclusions) != 1 {
		t.Fatalf("exclusions = %d, want 1", len(exclusions))
	}
	got := exclusions[0]
	if got.exists || got.path != filepath.Join(canonicalWorkspace, "build", "out", "secrets") || got.logicalPath != filepath.Join(workspace, "build", "out", "secrets") || got.firstMissing != filepath.Join(workspace, "build") {
		t.Fatalf("captured exclusion = exists %v path %q logical %q first missing %q", got.exists, got.path, got.logicalPath, got.firstMissing)
	}
	if _, err := revalidateFilesystemExclusions(exclusions, workspace, sessions); err != nil {
		t.Fatal(err)
	}
	// A later excluded name stays recognized by planning and source checks.
	if err := ValidateExclusionSources(exclusions, []string{workspace}); err == nil {
		t.Fatal("workspace bundle containing a missing exclusion accepted")
	}
	// Creating a missing ancestor before startup could plant a redirecting link,
	// so any creation of the highest missing component invalidates the capture.
	for _, create := range []func(string) error{
		func(path string) error { return os.Mkdir(path, 0700) },
		func(path string) error { return os.Symlink(root, path) },
	} {
		if err := create(filepath.Join(workspace, "build")); err != nil {
			t.Fatal(err)
		}
		if _, err := revalidateFilesystemExclusions(exclusions, workspace, sessions); err == nil {
			t.Fatal("missing ancestor creation accepted before startup")
		}
		if err := os.Remove(filepath.Join(workspace, "build")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := revalidateFilesystemExclusions(exclusions, workspace, sessions); err != nil {
		t.Fatalf("restored absence rejected: %v", err)
	}
}

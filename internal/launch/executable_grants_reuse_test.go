package launch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withExecutableDigestReuseMargin(t *testing.T, margin time.Duration) {
	t.Helper()
	previous := executableDigestReuseMargin
	executableDigestReuseMargin = margin
	t.Cleanup(func() { executableDigestReuseMargin = previous })
}

func resolveWorkspaceToolGrant(t *testing.T, contents string, settle time.Duration) (workspace, sessions, tool string, grants []ExecutableGrant) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace = filepath.Join(root, "workspace")
	sessions = filepath.Join(root, "sessions")
	tool = filepath.Join(workspace, "bin", "helper")
	writeExecutableFixture(t, tool, contents)
	time.Sleep(settle)
	grants, err = ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "helper", ReferenceKind: ExecutableReferenceWorkspaceRelative, Path: "bin/helper"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	return workspace, sessions, tool, grants
}

func TestExecutableGrantDigestIsComputedOncePerLaunch(t *testing.T) {
	withExecutableDigestReuseMargin(t, 20*time.Millisecond)
	before := executableDigestReads.Load()
	workspace, sessions, _, grants := resolveWorkspaceToolGrant(t, "helper-v1", 100*time.Millisecond)
	if got := executableDigestReads.Load() - before; got != 1 {
		t.Fatalf("resolve hashed %d times, want 1", got)
	}
	if !grants[0].digestReusable {
		t.Fatal("digest of a settled executable was not marked reusable")
	}
	for range 5 {
		revalidated, err := revalidateExecutableGrants(grants, workspace, sessions)
		if err != nil {
			t.Fatal(err)
		}
		if revalidated[0].digest != grants[0].digest {
			t.Fatal("revalidation changed the digest")
		}
	}
	if got := executableDigestReads.Load() - before; got != 1 {
		t.Fatalf("resolve + 5 revalidations hashed %d times, want 1", got)
	}
}

func TestExecutableGrantDigestReuseDetectsSameSizeRewriteWithRestoredMtime(t *testing.T) {
	withExecutableDigestReuseMargin(t, 20*time.Millisecond)
	workspace, sessions, tool, grants := resolveWorkspaceToolGrant(t, "helper-v1", 100*time.Millisecond)
	info, err := os.Stat(tool)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the coarse ctime clock tick so the rewrite gets a new ctime.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(tool, []byte("helper-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tool, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	before := executableDigestReads.Load()
	if _, err := revalidateExecutableGrants(grants, workspace, sessions); err == nil {
		t.Fatal("reused digest accepted a same-size rewrite with restored mtime")
	}
	if got := executableDigestReads.Load() - before; got != 1 {
		t.Fatalf("changed executable hashed %d times during revalidation, want 1", got)
	}
}

func TestExecutableGrantDigestOfRecentlyChangedFileIsNeverReused(t *testing.T) {
	withExecutableDigestReuseMargin(t, time.Hour)
	workspace, sessions, _, grants := resolveWorkspaceToolGrant(t, "helper-v1", 0)
	if grants[0].digestReusable {
		t.Fatal("digest of a file changed within the margin was marked reusable")
	}
	before := executableDigestReads.Load()
	for range 3 {
		if _, err := revalidateExecutableGrants(grants, workspace, sessions); err != nil {
			t.Fatal(err)
		}
	}
	if got := executableDigestReads.Load() - before; got != 3 {
		t.Fatalf("recent executable hashed %d times over 3 revalidations, want 3", got)
	}
}

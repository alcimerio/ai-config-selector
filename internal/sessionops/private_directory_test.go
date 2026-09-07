package sessionops

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateDirectoryScansUseAtomicCLOEXECIndependentDescriptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	scan, err := directory.openScan()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(scan.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("scan descriptor is inheritable")
	}
	_ = scan.Close()
	first, err := directory.entries(16)
	if err != nil {
		t.Fatal(err)
	}
	second, err := directory.entries(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("repeated scans = %d, %d", len(first), len(second))
	}
}

func TestPrivateDirectoryAppliesLimitBeforeReturningEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three", "four"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if entries, err := directory.entries(3); err == nil || entries != nil {
		t.Fatalf("over-limit scan = (%v, %v)", entries, err)
	}
}

func TestPrivateDirectoryLockRejectsHardLinkBeforeModeMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(path, "session.lock")); err != nil {
		t.Fatal(err)
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if file, err := directory.lock("session.lock", true); err == nil {
		file.Close()
		t.Fatal("hard-linked lock accepted")
	}
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("victim mode mutated to %o", info.Mode().Perm())
	}
}

func TestPrivateChildRejectsParentReplacementWithoutFollowingNewPath(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "private")
	if err := os.Mkdir(basePath, 0o700); err != nil {
		t.Fatal(err)
	}
	base, err := pinPrivateDirectory(basePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.close()
	child, err := pinPrivateChild(base, "records", true)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	displaced := filepath.Join(root, "displaced")
	if err := os.Rename(basePath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(basePath, "records"), 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(basePath, "records", "decoy")
	if err := os.WriteFile(decoy, []byte("must remain unread"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := child.entries(8); err == nil {
		t.Fatal("pinned child accepted a replaced parent path")
	}
	if got, err := os.ReadFile(decoy); err != nil || string(got) != "must remain unread" {
		t.Fatalf("replacement path changed = (%q, %v)", got, err)
	}
}

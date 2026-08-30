package codexauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileIdentityLockerRejectsConcurrentUseAndReleases(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "locks")
	locker := newFileIdentityLocker(directory)
	first, err := locker.TryLock("work")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locker.TryLock("work"); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("concurrent lock error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := locker.TryLock("work")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("lock directory mode = %o", info.Mode().Perm())
	}
	lockInfo, err := os.Stat(filepath.Join(directory, "work.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %o", lockInfo.Mode().Perm())
	}
}

func TestFileIdentityLockerRejectsSymlinkLockFile(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "locks")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "work.lock")); err != nil {
		t.Fatal(err)
	}

	if _, err := newFileIdentityLocker(directory).TryLock("work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("symlink lock error = %v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "sentinel" {
		t.Fatalf("symlink target changed: %q, %v", contents, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode changed to %o", info.Mode().Perm())
	}
}

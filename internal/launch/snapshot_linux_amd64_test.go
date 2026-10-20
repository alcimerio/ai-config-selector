//go:build linux && amd64

package launch

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxSnapshotIdentityMatchesNonFollowingStat(t *testing.T) {
	root := t.TempDir()
	tree := filepath.Join(root, "tree")
	nested := filepath.Join(tree, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o2755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "data.txt")
	if err := os.WriteFile(file, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(nested, "alias.txt")
	if err := os.Link(file, alias); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(tree, "pipe")
	if err := unix.Mkfifo(fifo, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tree, "link")
	if err := os.Symlink("nested/data.txt", link); err != nil {
		t.Fatal(err)
	}
	procLink := filepath.Join(tree, "proc-link")
	if err := os.Symlink("/proc/version", procLink); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "hidden"), []byte("no"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "dir-link")
	if err := os.Symlink(outside, dirLink); err != nil {
		t.Fatal(err)
	}

	snapshot, err := linuxCaptureSnapshot([]string{tree, dirLink, filepath.Join(root, "missing"), ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snapshot[filepath.Join(root, "missing")]; exists {
		t.Fatal("missing root was recorded")
	}
	if _, exists := snapshot[filepath.Join(dirLink, "hidden")]; exists {
		t.Fatal("snapshot followed a directory symlink")
	}
	dirNode, ok := snapshot[dirLink]
	if !ok || dirNode.identity.mode&os.ModeSymlink == 0 || len(dirNode.children) != 0 {
		t.Fatalf("directory symlink node = %+v", dirNode)
	}

	var sawFile bool
	for path, node := range snapshot {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("stat unavailable")
		}
		want := identityFromFileInfo(info, stat)
		if node.identity != want {
			t.Fatalf("%s identity %+v != lstat %+v", path, node.identity, want)
		}
		if node.mountID == 0 {
			t.Fatalf("%s missing mount id", path)
		}
		if info.Mode()&os.ModeSymlink == 0 && info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(node.children) {
				t.Fatalf("%s children = %v", path, node.children)
			}
			for index, entry := range entries {
				if entry.Name() != node.children[index] {
					t.Fatalf("%s children = %v", path, node.children)
				}
			}
		} else if len(node.children) != 0 {
			t.Fatalf("%s recorded children %v", path, node.children)
		}
		if path == file {
			sawFile = true
			var filesystem unix.Statfs_t
			if unix.Statfs(path, &filesystem) != nil || node.filesystemType != filesystem.Type {
				t.Fatalf("file filesystem %d", node.filesystemType)
			}
		}
	}
	if !sawFile {
		t.Fatal("file missing from snapshot")
	}
	procNode := snapshot[procLink]
	if procNode.filesystemType != unix.PROC_SUPER_MAGIC {
		t.Fatalf("followed symlink filesystem = %d", procNode.filesystemType)
	}
	if snapshot[tree].filesystemType == unix.PROC_SUPER_MAGIC {
		t.Fatal("symlink filesystem poisoned the mount cache")
	}
	if snapshot[file].identity.links != 2 {
		t.Fatalf("links = %d", snapshot[file].identity.links)
	}
}

func BenchmarkLinuxCaptureSnapshot(b *testing.B) {
	root := b.TempDir()
	const files = 4096
	for index := 0; index < files; index++ {
		directory := filepath.Join(root, fmt.Sprintf("d%d", index/64))
		if index%64 == 0 {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				b.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("f%d.txt", index)), []byte("x"), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		tree, err := linuxCaptureSnapshot([]string{root})
		if err != nil || len(tree) < files {
			b.Fatalf("snapshot: %v entries=%d", err, len(tree))
		}
	}
}

package profilerepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEveryFilesystemFailureIsReportedAndRecoverable(t *testing.T) {
	injected := errors.New("injected filesystem failure")
	for _, op := range []string{"create", "replace", "clone", "rename", "delete"} {
		t.Run(op, func(t *testing.T) {
			for _, point := range trace(t, seeded(t), "apply", op) {
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					fired := false
					r.hook = func(p string) error {
						if p == point && !fired {
							fired = true
							return injected
						}
						return nil
					}
					out, err := r.Apply(context.Background(), operation(op))
					if !fired || !errors.Is(err, injected) {
						t.Fatalf("failure hidden: %+v %v", out, err)
					}
					if out.State == NotCommitted {
						source, _ := r.Read(context.Background(), "source")
						destination, _ := r.Read(context.Background(), "destination")
						if string(source.Bytes) != oldBytes || destination.Exists {
							t.Fatalf("false not-committed: %+v", out)
						}
					}
					r.hook = nil
					recoverFreshTwice(t, r)
					assertSettled(t, r, op)
				})
			}
		})
	}
}
func TestCancellationAndCleanupOutcomes(t *testing.T) {
	for _, point := range []string{"stage.write.after", "plan.directory-sync.after", "decision.publish.after", "publish.link.after", "complete.sync.after"} {
		t.Run(point, func(t *testing.T) {
			r := seeded(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.hook = func(p string) error {
				if p == point {
					cancel()
				}
				return nil
			}
			out, err := r.Apply(ctx, operation("create"))
			before := strings.HasPrefix(point, "stage.") || strings.HasPrefix(point, "plan.")
			if before {
				if out.State != NotCommitted || !errors.Is(err, context.Canceled) {
					t.Fatalf("predecision cancellation: %+v %v", out, err)
				}
			} else if out.State != Committed || err != nil {
				t.Fatalf("postdecision settlement: %+v %v", out, err)
			}
			r.hook = nil
			assertSettled(t, r, "create")
		})
	}
	t.Run("primary-and-abort-cleanup", func(t *testing.T) {
		r := seeded(t)
		primary, cleanup := errors.New("write failure"), errors.New("cleanup failure")
		r.hook = func(p string) error {
			switch p {
			case "stage.write.before":
				return primary
			case "cleanup.stage.before":
				return cleanup
			}
			return nil
		}
		out, err := r.Apply(context.Background(), operation("create"))
		if out.State != NotCommitted || !out.RecoveryRequired || !errors.Is(err, primary) || !errors.Is(err, cleanup) {
			t.Fatalf("lost primary/cleanup: %+v %v", out, err)
		}
		r.hook = nil
		recoverFreshTwice(t, r)
	})
	t.Run("short-write", func(t *testing.T) {
		r := seeded(t)
		r.write = func(f *os.File, data []byte) (int, error) { return f.Write(data[:len(data)/2]) }
		out, err := r.Apply(context.Background(), operation("create"))
		if out.State != NotCommitted || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write: %+v %v", out, err)
		}
		recoverFreshTwice(t, r)
		assertSettled(t, r, "create")
	})
}
func TestExclusivePublicationAndObservedInterference(t *testing.T) {
	for _, op := range []string{"create", "clone", "rename"} {
		t.Run(op, func(t *testing.T) {
			r := seeded(t)
			path := filepath.Join(r.acsHome, "profiles", "destination.json")
			r.hook = func(p string) error {
				if p == "publish.link.before" {
					return helper(r.acsHome, "occupy", "", "").Run()
				}
				return nil
			}
			out, err := r.Apply(context.Background(), operation(op))
			if err == nil || out.State != Unknown {
				t.Fatalf("destination race: %+v %v", out, err)
			}
			r.hook = nil
			for i := 0; i < 2; i++ {
				out, err = r.Recover(context.Background())
				if err == nil || out.State != Unknown {
					t.Fatalf("equal bytes are not publication proof: %+v %v", out, err)
				}
			}
			got, _ := os.ReadFile(path)
			source, _ := os.ReadFile(filepath.Join(r.acsHome, "profiles", "source.json"))
			if string(got) != newBytes || string(source) != oldBytes {
				t.Fatal("occupied destination or source changed")
			}
		})
	}
	t.Run("source-inode-replaced-with-equal-bytes", func(t *testing.T) {
		r := seeded(t)
		path := filepath.Join(r.acsHome, "profiles", "source.json")
		r.hook = func(p string) error {
			if p == "decision.publish.after" {
				if e := os.Remove(path); e != nil {
					return e
				}
				return os.WriteFile(path, []byte(oldBytes), 0600)
			}
			return nil
		}
		// Keep the original inode allocated so a filesystem cannot reuse its number.
		original, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer original.Close()
		out, err := r.Apply(context.Background(), operation("replace"))
		if err == nil || out.State != Unknown {
			t.Fatalf("outside source replacement: %+v %v", out, err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != oldBytes {
			t.Fatal("overwrote observed outside writer")
		}
	})
	t.Run("lock-path-replacement", func(t *testing.T) {
		r := seeded(t)
		path := filepath.Join(r.acsHome, "profiles", leaf("lock"))
		r.hook = func(p string) error {
			if p == "stage.write.after" {
				if e := os.Rename(path, path+"-moved"); e != nil {
					return e
				}
				return os.WriteFile(path, nil, 0600)
			}
			return nil
		}
		out, err := r.Apply(context.Background(), operation("create"))
		if err == nil || out.State != NotCommitted || !out.RecoveryRequired {
			t.Fatalf("replaced lock accepted: %+v %v", out, err)
		}
	})
}
func TestMalformedAndUnsafeArtifactsArePreserved(t *testing.T) {
	for _, kind := range []string{"unknown-version", "duplicate", "trailing", "path", "oversize", "unknown-artifact", "symlink", "fifo", "directory", "hardlink", "mode", "case-alias"} {
		t.Run(kind, func(t *testing.T) {
			r := seeded(t)
			dir := filepath.Join(r.acsHome, "profiles")
			path := filepath.Join(dir, leaf("plan"))
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(sentinel, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(sentinel, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(sentinel, path); err != nil {
					t.Fatal(err)
				}
			default:
				data := []byte(`{"Version":999}`)
				switch kind {
				case "duplicate":
					data = []byte(`{"Version":1,"Version":999}`)
				case "trailing":
					data = []byte(`{} {}`)
				case "path":
					data = []byte(`{"Version":1,"Source":"../../sentinel"}`)
				case "oversize":
					data = bytes.Repeat([]byte("x"), maxMetadataBytes+1)
				case "unknown-artifact":
					path = filepath.Join(dir, leaf("future"))
				case "case-alias":
					path = filepath.Join(dir, strings.ToUpper(leaf("plan")))
				}
				mode := os.FileMode(0600)
				if kind == "mode" {
					mode = 0644
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, err = r.Recover(context.Background()); err == nil {
					t.Fatal("unsafe recovery accepted")
				}
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("unsafe input modified", err)
			}
			got, _ := os.ReadFile(sentinel)
			if string(got) != "outside" {
				t.Fatal("outside sentinel changed")
			}
		})
	}
}
func TestRepositoryBoundsAndUnsafePublicEntries(t *testing.T) {
	r := seeded(t)
	ctx := context.Background()
	for _, name := range []string{"", "../escape", strings.Repeat("a", 65), "a/b", "\x00"} {
		if _, err := r.Read(ctx, name); err == nil {
			t.Fatal("invalid name", name)
		}
	}
	if _, err := r.Apply(ctx, CreateRequest{"destination", revision("destination", false, nil), make([]byte, MaxDocumentBytes+1)}); err == nil {
		t.Fatal("document bound")
	}
	for _, kind := range []string{"symlink", "fifo", "directory", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			r := seeded(t)
			p := filepath.Join(r.acsHome, "profiles", "destination.json")
			switch kind {
			case "symlink":
				_ = os.Symlink("source.json", p)
			case "fifo":
				_ = syscall.Mkfifo(p, 0600)
			case "directory":
				_ = os.Mkdir(p, 0700)
			case "hardlink":
				_ = os.Link(filepath.Join(r.acsHome, "profiles", "source.json"), p)
			}
			if _, err := r.Apply(ctx, operation("create")); err == nil {
				t.Fatal("occupied unsafe destination overwritten")
			}
			if _, err := r.Apply(ctx, DeleteRequest{"destination", revision("destination", true, []byte(oldBytes))}); err == nil {
				t.Fatal("unsafe entry deleted")
			}
		})
	}
}
func TestRestrictedIdentityPermissionDenial(t *testing.T) {
	parent, err := os.MkdirTemp("", "acs-repository-permission-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	if err = os.Chmod(parent, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	root := filepath.Join(parent, "acs")
	if os.Geteuid() == 0 {
		// Copy the test executable out of a possibly root-only Go build directory.
		executable, err := os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(parent, "permission-test")
		if err = os.WriteFile(binary, executable, 0755); err != nil {
			t.Fatal(err)
		}
		cmd := helper(root, "restricted", "", "")
		cmd.Path = binary
		cmd.Args[0] = binary
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restricted child: %v %s", err, output)
		}
	} else {
		if err = os.Mkdir(root, 0700); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("identity is not actually denied: %v", err)
		}
		out, err := New(root).Apply(context.Background(), operation("create"))
		if !errors.Is(err, os.ErrPermission) || out.State != NotCommitted {
			t.Fatalf("permission denial: %+v %v", out, err)
		}
	}
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restricted mutation created root", err)
	}
}

func TestPinnedRepositoryReplacementNeverWritesOutside(t *testing.T) {
	r := seeded(t)
	directory := filepath.Join(r.acsHome, "profiles")
	moved := filepath.Join(r.acsHome, "retained-profiles")
	outside := t.TempDir()
	r.hook = func(point string) error {
		if point == "stage.write.after" {
			if err := os.Rename(directory, moved); err != nil {
				return err
			}
			return os.Symlink(outside, directory)
		}
		return nil
	}
	out, err := r.Apply(context.Background(), operation("create"))
	if err == nil || out.State != NotCommitted || !out.RecoveryRequired {
		t.Fatalf("directory replacement accepted: %+v %v", out, err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("outside directory changed", err)
	}
	original, err := os.ReadFile(filepath.Join(moved, "source.json"))
	if err != nil || string(original) != oldBytes {
		t.Fatal("pinned original source changed", err)
	}
}
func TestRecoveryBoundsEnumerationAndPreservesFuturePreparation(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		r := seeded(t)
		for i := 0; i < maxEntries; i++ {
			if err := os.WriteFile(filepath.Join(r.acsHome, "profiles", fmt.Sprintf("unrelated-%d", i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.Recover(context.Background()); !errors.Is(err, ErrUnsafe) {
			t.Fatal("unbounded enumeration", err)
		}
	})
	t.Run("future-preparation", func(t *testing.T) {
		r := seeded(t)
		path := filepath.Join(r.acsHome, "profiles", leaf("pending"))
		data := []byte(`{"Version":2}`)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Recover(context.Background()); err == nil {
			t.Fatal("future preparation removed")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("future preparation changed", err)
		}
	})
}

func TestRecoveryFailuresPreserveEvidenceAndConverge(t *testing.T) {
	failure := errors.New("recovery filesystem failure")
	for _, initial := range []string{"stage.write.after", "decision.publish.after", "cleanup.stage.after"} {
		t.Run(initial, func(t *testing.T) {
			baseline := seeded(t)
			runKilled(t, baseline, "apply", "rename", initial)
			for _, point := range trace(t, baseline, "recover", "rename") {
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					runKilled(t, r, "apply", "rename", initial)
					fired := false
					r.hook = func(p string) error {
						if p == point && !fired {
							fired = true
							return failure
						}
						return nil
					}
					_, err := r.Recover(context.Background())
					if !fired || !errors.Is(err, failure) {
						t.Fatal("recovery error hidden", err)
					}
					r.hook = nil
					recoverFreshTwice(t, r)
					assertSettled(t, r, "rename")
				})
			}
		})
	}
}

func TestMalformedPreparationPrefixesRemainPreserved(t *testing.T) {
	for _, data := range []string{
		`{"Version":1,"ID":"INVALID!`,
		`{"Version":1,"ID":"00000000000000000000000000000000","Unknown":true,`,
		`{"Version":1,"ID":"00000000000000000000000000000000","Operation":garbage}`,
	} {
		t.Run(data, func(t *testing.T) {
			r := seeded(t)
			path := filepath.Join(r.acsHome, "profiles", leaf("pending"))
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				out, err := r.Recover(context.Background())
				if err == nil || !out.RecoveryRequired {
					t.Fatalf("malformed evidence removed: %+v %v", out, err)
				}
				got, e := os.ReadFile(path)
				if e != nil || string(got) != data {
					t.Fatal("malformed evidence changed", e)
				}
			}
		})
	}
}
func TestTerminalCleanupRejectsUnexplainedLinksAndSwap(t *testing.T) {
	for _, kind := range []string{"outside-link", "impossible-swap"} {
		t.Run(kind, func(t *testing.T) {
			r := seeded(t)
			runKilled(t, r, "apply", "create", "complete.publish.after")
			directory := filepath.Join(r.acsHome, "profiles")
			stage := filepath.Join(directory, leaf("stage"))
			extra := filepath.Join(t.TempDir(), "outside-link")
			if kind == "impossible-swap" {
				extra = filepath.Join(directory, leaf("swap"))
			}
			if err := os.Link(stage, extra); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				out, err := r.Recover(context.Background())
				if err == nil || !out.RecoveryRequired {
					t.Fatalf("terminal interference accepted: %+v %v", out, err)
				}
				for _, name := range []string{"stage", "complete"} {
					if _, err := os.Stat(filepath.Join(directory, leaf(name))); err != nil {
						t.Fatal("evidence removed", err)
					}
				}
			}
			if err := os.Remove(extra); err != nil {
				t.Fatal(err)
			}
			recoverFreshTwice(t, r)
			assertSettled(t, r, "create")
		})
	}
}
func TestPreparationRejectsSubstitutedDesiredBytes(t *testing.T) {
	for _, test := range []struct {
		name                 string
		desired, replacement []byte
	}{
		{"nonempty-desired", []byte(newBytes), []byte("outside bytes")},
		{"empty-desired", nil, []byte("outside bytes")},
		{"emptied-stage", []byte(newBytes), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := seeded(t)
			r.hook = func(point string) error {
				if point == "stage.close.after" {
					return os.WriteFile(filepath.Join(r.acsHome, "profiles", leaf("stage")), test.replacement, 0600)
				}
				return nil
			}
			expected, _ := AbsentRevision("destination")
			out, err := r.Apply(context.Background(), CreateRequest{"destination", expected, test.desired})
			if err == nil || out.State != NotCommitted {
				t.Fatalf("substituted stage committed: %+v %v", out, err)
			}
			r.hook = nil
			recoverFreshTwice(t, r)
			assertSettled(t, r, "create")
		})
	}
}

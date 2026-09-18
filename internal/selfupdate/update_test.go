package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVersionOrdering(t *testing.T) {
	for _, s := range []string{"v1.2.3", "v10.0.0"} {
		if _, e := ParseVersion(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"1.2.3", "v1.02.3", "v1.2", "v1.2.3-rc1", "v18446744073709551616.0.0"} {
		if _, e := ParseVersion(s); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	a, _ := ParseVersion("v0.9.0")
	b, _ := ParseVersion("v0.10.0")
	if Compare(a, b) >= 0 {
		t.Fatal("lexical version ordering")
	}
}
func TestHistoricalManifest(t *testing.T) {
	name := "acs_0.3.3_darwin_arm64.tar.gz"
	hash := strings.Repeat("a", 64)
	rows := []string{hash + "  acs_0.3.3_darwin_amd64.tar.gz", hash + "  " + name, hash + "  acs_0.3.3_linux_arm64.tar.gz", hash + "  acs_0.3.3_linux_amd64.tar.gz"}
	if _, e := checksum([]byte(strings.Join(rows, "\n")+"\n"), name); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Join(append(rows, rows[1]), "\n"), hash + "  ../" + name, hash + "  acs_0.3.4_darwin_arm64.tar.gz", strings.Join(rows[:1], "\n")} {
		if _, e := checksum([]byte(bad), name); e == nil {
			t.Fatalf("accepted malformed manifest %q", bad)
		}
	}
}
func makeArchive(t *testing.T, names []string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	w := tar.NewWriter(z)
	for _, name := range names {
		v := []byte("payload")
		if e := w.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(v)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := w.Write(v); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestArchiveSafety(t *testing.T) {
	good := makeArchive(t, []string{"acs", "README.md", "LICENSE"})
	if _, e := extract(good); e != nil {
		t.Fatal(e)
	}
	for _, names := range [][]string{{"acs", "README.md", "../LICENSE"}, {"acs", "acs", "README.md", "LICENSE"}, {"acs", "README.md"}} {
		if _, e := extract(makeArchive(t, names)); e == nil {
			t.Fatalf("accepted %v", names)
		}
	}
	if _, e := extract(good[:len(good)-4]); e == nil {
		t.Fatal("accepted truncated gzip")
	}
}
func TestCheckOnlyUsesMetadata(t *testing.T) {
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/latest" {
			t.Errorf("unexpected asset fetch %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"tag_name":"v0.10.0","assets":[{"name":"acs_0.10.0_darwin_arm64.tar.gz","browser_download_url":"%s/archive"},{"name":"SHA256SUMS","browser_download_url":"%s/manifest"}]}`, server.URL, server.URL)
	}))
	defer server.Close()
	got, e := Run(context.Background(), "v0.9.0", "", true, Config{APIBase: server.URL, Client: server.Client(), PlatformOS: "darwin", PlatformArch: "arm64"})
	if e != nil || !got.Available || got.Target != "v0.10.0" || requests != 1 {
		t.Fatalf("got %+v, %v, requests %d", got, e, requests)
	}
}
func TestReplacementAndIdentityFence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acs")
	old := []byte("old executable")
	if e := os.WriteFile(path, old, 0755); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Lstat(path)
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	_, hash, e := installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	if e := replace(context.Background(), path, []byte("new executable"), st, hash, d); e != nil {
		t.Fatal(e)
	}
	now, _ := os.ReadFile(path)
	if string(now) != "new executable" {
		t.Fatalf("not replaced: %q", now)
	}
	if e := replace(context.Background(), path, []byte("third executable"), st, hash, d); e == nil {
		t.Fatal("stale destination accepted")
	}
	now, _ = os.ReadFile(path)
	if string(now) != "new executable" {
		t.Fatal("stale update modified destination")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st, _ = os.Lstat(path)
	_, hash, e = installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	if e := replace(ctx, path, []byte("fourth executable"), st, hash, d); e == nil {
		t.Fatal("cancelled update succeeded")
	}
	now, _ = os.ReadFile(path)
	if string(now) != "new executable" {
		t.Fatal("cancelled update modified destination")
	}
}
func TestChecksumMismatchLeavesOldBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acs")
	old := []byte("original")
	if e := os.WriteFile(path, old, 0755); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("different"))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  acs_0.5.0_darwin_arm64.tar.gz\n")
	archive := makeArchive(t, []string{"acs", "README.md", "LICENSE"})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tags/v0.5.0":
			fmt.Fprintf(w, `{"tag_name":"v0.5.0","assets":[{"name":"acs_0.5.0_darwin_arm64.tar.gz","browser_download_url":"%s/archive"},{"name":"SHA256SUMS","browser_download_url":"%s/manifest"}]}`, server.URL, server.URL)
		case "/manifest":
			w.Write(manifest)
		case "/archive":
			w.Write(archive)
		}
	}))
	defer server.Close()
	_, e := Run(context.Background(), "v0.4.0", "v0.5.0", false, Config{APIBase: server.URL, Client: server.Client(), Executable: path, PlatformOS: "darwin", PlatformArch: "arm64"})
	if e == nil || !strings.Contains(e.Error(), "checksum mismatch") {
		t.Fatalf("error %v", e)
	}
	now, _ := os.ReadFile(path)
	if !bytes.Equal(now, old) {
		t.Fatal("old executable changed")
	}
}

type mutateAtCommit struct {
	context.Context
	action func()
	once   bool
}

func (m *mutateAtCommit) Err() error {
	if !m.once {
		m.once = true
		m.action()
	}
	return nil
}
func TestStageSubstitutionRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acs")
	if e := os.WriteFile(path, []byte("old"), 0755); e != nil {
		t.Fatal(e)
	}
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	original, hash, e := installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	var substituted string
	ctx := &mutateAtCommit{Context: context.Background(), action: func() {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".acs.update.") && entry.Name() != ".acs.update.lock" {
				substituted = filepath.Join(dir, entry.Name())
				break
			}
		}
		if substituted == "" {
			t.Fatal("stage not found")
		}
		replacement := filepath.Join(dir, "foreign")
		if e := os.WriteFile(replacement, []byte("unverified"), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(replacement, substituted); e != nil {
			t.Fatal(e)
		}
	}}
	if e := replace(ctx, path, []byte("verified"), original, hash, d); e == nil {
		t.Fatal("published substituted stage")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatalf("destination changed: %q", got)
	}
	got, _ = os.ReadFile(substituted)
	if string(got) != "unverified" {
		t.Fatal("cleanup removed foreign replacement")
	}
}
func TestSameInodeRewriteRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acs")
	if e := os.WriteFile(path, []byte("old"), 0755); e != nil {
		t.Fatal(e)
	}
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	original, hash, e := installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("changed"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := replace(context.Background(), path, []byte("new"), original, hash, d); e == nil {
		t.Fatal("overwrote same-inode rewrite")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "changed" {
		t.Fatal("concurrent bytes changed")
	}
}
func TestArchiveRejectsOversizedTailAndMissingTrailer(t *testing.T) {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	tw := tar.NewWriter(z)
	for _, name := range []string{"acs", "README.md", "LICENSE"} {
		payload := []byte("x")
		if e := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0755, Size: 1}); e != nil {
			t.Fatal(e)
		}
		tw.Write(payload)
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := z.Write(bytes.Repeat([]byte("x"), 100<<10)); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{b.Bytes(), b.Bytes()[:b.Len()-8]} {
		if _, e := extract(raw); e == nil {
			t.Fatal("accepted malformed archive tail")
		}
	}
}
func TestArchiveRejectsSecondGzipMember(t *testing.T) {
	first := makeArchive(t, []string{"acs", "README.md", "LICENSE"})
	var second bytes.Buffer
	z := gzip.NewWriter(&second)
	_, _ = z.Write([]byte{0, 0, 0})
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := extract(append(first, second.Bytes()...)); e == nil {
		t.Fatal("accepted concatenated gzip member")
	}
}

func TestStageModeChangeRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acs")
	if e := os.WriteFile(path, []byte("old"), 0755); e != nil {
		t.Fatal(e)
	}
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	original, hash, e := installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	ctx := &mutateAtCommit{Context: context.Background(), action: func() {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".acs.update.") && entry.Name() != ".acs.update.lock" {
				if e = os.Chmod(filepath.Join(dir, entry.Name()), 0644); e != nil {
					t.Fatal(e)
				}
				return
			}
		}
		t.Fatal("stage missing")
	}}
	if e := replace(ctx, path, []byte("new"), original, hash, d); e == nil {
		t.Fatal("published non-executable stage")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatal("old executable changed")
	}
}
func TestNamedFIFORefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	fifo := filepath.Join(dir, "acs")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, _, e := installedIdentity(d, "acs"); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO read blocked")
	}
}
func TestPublicationBoundaryFailures(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(fmt.Sprint("post=", post), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "acs")
			if e := os.WriteFile(path, []byte("old"), 0755); e != nil {
				t.Fatal(e)
			}
			d, e := pinDirectory(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			original, hash, e := installedIdentity(d, "acs")
			if e != nil {
				t.Fatal(e)
			}
			rename := unix.Renameat
			syncDir := func(f *os.File) error { return f.Sync() }
			if post {
				syncDir = func(*os.File) error { return errors.New("injected sync failure") }
			} else {
				rename = func(int, string, int, string) error { return errors.New("injected rename failure") }
			}
			e = replaceWithOps(context.Background(), path, []byte("new"), original, hash, d, rename, syncDir)
			if e == nil {
				t.Fatal("failure ignored")
			}
			got, _ := os.ReadFile(path)
			if post {
				if string(got) != "new" || !errors.Is(e, ErrPublishedUncertain) {
					t.Fatalf("postpublication outcome: %q %v", got, e)
				}
			} else if string(got) != "old" || errors.Is(e, ErrPublishedUncertain) {
				t.Fatalf("prepublication outcome: %q %v", got, e)
			}
		})
	}
}
func TestStageOperationFailuresKeepOldBytesAndCleanOwnedStage(t *testing.T) {
	for _, kind := range []string{"write", "chmod", "sync"} {
		t.Run(kind, func(t *testing.T) {
			p, d, st, h := reviewInstall(t)
			write := func(f *os.File, b []byte) (int, error) { return f.Write(b) }
			chmod := func(f *os.File, m os.FileMode) error { return f.Chmod(m) }
			syncStage := func(f *os.File) error { return f.Sync() }
			switch kind {
			case "write":
				write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write failure") }
			case "chmod":
				chmod = func(*os.File, os.FileMode) error { return errors.New("injected chmod failure") }
			case "sync":
				syncStage = func(*os.File) error { return errors.New("injected file sync failure") }
			}
			e := replaceWithStageOps(context.Background(), p, []byte("new"), st, h, d, unix.Renameat, func(f *os.File) error { return f.Sync() }, write, chmod, syncStage)
			if e == nil {
				t.Fatal("stage fault ignored")
			}
			body, _ := os.ReadFile(p)
			if string(body) != "old" {
				t.Fatal("old executable changed")
			}
			entries, e := os.ReadDir(filepath.Dir(p))
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".acs.update.") && entry.Name() != ".acs.update.lock" {
					t.Fatalf("owned stage left behind: %s", entry.Name())
				}
			}
		})
	}
}
func reviewInstall(t *testing.T) (string, *os.File, os.FileInfo, [32]byte) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "acs")
	if e := os.WriteFile(p, []byte("old"), 0755); e != nil {
		t.Fatal(e)
	}
	d, e := pinDirectory(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	st, h, e := installedIdentity(d, "acs")
	if e != nil {
		t.Fatal(e)
	}
	return p, d, st, h
}
func TestContendedLockCancellation(t *testing.T) {
	p, d, st, h := reviewInstall(t)
	fd, e := unix.Openat(int(d.Fd()), ".acs.update.lock", unix.O_CREAT|unix.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		t.Fatal(e)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- replace(ctx, p, []byte("new"), st, h, d) }()
	select {
	case e := <-done:
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatalf("%v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("lock cancellation blocked")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "old" {
		t.Fatal("mutated destination")
	}
}
func TestAncestorAliasRefused(t *testing.T) {
	p, d, st, h := reviewInstall(t)
	dir := filepath.Dir(p)
	moved := dir + "-moved"
	defer os.RemoveAll(moved)
	ctx := &mutateAtCommit{Context: context.Background(), action: func() {
		if e := os.Rename(dir, moved); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink(moved, dir); e != nil {
			t.Fatal(e)
		}
	}}
	if e := replace(ctx, p, []byte("new"), st, h, d); e == nil {
		t.Fatal("accepted alias")
	}
	b, _ := os.ReadFile(filepath.Join(moved, "acs"))
	if string(b) != "old" {
		t.Fatal("changed old executable")
	}
}
func TestPostPublicationCancellation(t *testing.T) {
	p, d, st, h := reviewInstall(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := replaceWithOps(ctx, p, []byte("new"), st, h, d, unix.Renameat, func(*os.File) error { cancel(); return nil })
	if !errors.Is(e, ErrPublishedUncertain) {
		t.Fatalf("%v", e)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatal("lost publication")
	}
}
func TestExpandedReaderBudget(t *testing.T) {
	r := &expandedReader{source: strings.NewReader(strings.Repeat("x", 100)), limit: 10}
	if _, e := io.ReadAll(r); e == nil {
		t.Fatal("budget ignored")
	}
}

package acceptance_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type devinHookMarkerLeafPending struct{}

func (devinHookMarkerLeafPending) Error() string { return "fixed marker leaf pending" }

func TestHookFixedMarkerRejectsUnsafeOrUnknownFiles(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(dir, "valid")
	if err := os.WriteFile(valid, []byte("invalid-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookFixedMarker(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookFixedMarker(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing marker unexpectedly accepted as valid")
	} else {
		var pending devinHookMarkerLeafPending
		if !errors.As(err, &pending) {
			t.Fatalf("missing marker not classified as pending: %v", err)
		}
	}
	for name, data := range map[string]string{"unknown": "raw-event\n", "oversize": strings.Repeat("x", 65)} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHookFixedMarker(p); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookFixedMarker(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := readHookFixedMarker(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted missing marker")
	}
	if _, err := readHookFixedMarker(dir); err == nil {
		t.Fatal("accepted directory marker")
	}
	aliasDir := filepath.Join(dir, "alias-dir")
	if err := os.Symlink(dir, aliasDir); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookFixedMarker(filepath.Join(aliasDir, "valid")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookFixedMarker(fifo); err == nil {
		t.Fatal("accepted FIFO")
	}
}

func readHookFixedMarker(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", errors.New("fixed marker path invalid")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("fixed marker root unavailable")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			if i == len(parts)-1 && openErr == unix.ENOENT {
				return "", devinHookMarkerLeafPending{}
			}
			return "", errors.New("fixed marker unavailable")
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "hook-fixed-marker")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 64 {
		return "", errors.New("fixed marker shape")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || int64(len(b)) != st.Size() {
		return "", errors.New("fixed marker read")
	}
	code := strings.TrimSuffix(string(b), "\n")
	allowed := map[string]bool{"invoked": true, "invalid-json": true, "event-name-missing": true, "event-name-unexpected": true, "session-id-invalid": true, "session-id-empty": true, "prompt-id-present": true, "duplicate-key": true, "read-timeout": true, "missing-input-expectation": true, "input-mismatch": true, "selected-input-read": true, "executable-read": true, "write-denial-missing": true, "receipt-publication": true, "witness-failed": true}
	if !allowed[code] {
		return "", errors.New("fixed marker classification")
	}
	return code, nil
}

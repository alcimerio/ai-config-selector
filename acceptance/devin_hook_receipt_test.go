package acceptance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Receipt claims are not independent process or lifecycle evidence. The native
// consumer supplies independently observed HOME/helper/input expectations.
type devinHookReceipt struct {
	Event             string `json:"event"`
	SessionID         string `json:"session_id"` // vendor ID, not ACS capability ID
	SessionHome       string `json:"session_home"`
	PID               int    `json:"pid"`
	PPID              int    `json:"ppid"`
	Executable        string `json:"executable"`
	ExecutableSHA256  string `json:"executable_sha256"`
	InputSHA256       string `json:"input_sha256"`
	InputWriteError   string `json:"input_write_error"`
	OutsideWriteError string `json:"outside_write_error"`
	ConfigWriteError  string `json:"config_write_error"`
}
type devinHookReceiptExpected struct{ SessionHome, Executable, ExecutableSHA256, InputSHA256 string }
type devinHookReceiptSnapshot struct {
	Receipt devinHookReceipt
	info    os.FileInfo
	digest  [sha256.Size]byte
	// Only records a successful caller-supplied verifier; never means natural exit.
	ProcessVerified bool
}

func validDevinHookDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

// Canonical absolute paths only. Reject aliases at every component; nonblocking
// open prevents a substituted FIFO from hanging receipt polling.
func openDevinHookReceipt(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("hook receipt path invalid")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("hook receipt root unavailable")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, name, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, errors.New("hook receipt unavailable")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "hook-receipt"), nil
}
func readDevinHookReceipt(path string, want devinHookReceiptExpected, verifyProcess func(int, int) error) (devinHookReceiptSnapshot, error) {
	var result devinHookReceiptSnapshot
	if !filepath.IsAbs(want.SessionHome) || filepath.Clean(want.SessionHome) != want.SessionHome || !filepath.IsAbs(want.Executable) || filepath.Clean(want.Executable) != want.Executable || !validDevinHookDigest(want.ExecutableSHA256) || !validDevinHookDigest(want.InputSHA256) {
		return result, errors.New("independent hook expectations incomplete")
	}
	f, e := openDevinHookReceipt(path)
	if e != nil {
		return result, e
	}
	defer f.Close()
	before, e := f.Stat()
	const limit = 4096
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 1 || before.Size() > limit {
		return result, errors.New("hook receipt type mode or size")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || len(b) > limit {
		return result, errors.New("hook receipt read bound")
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(b)) != after.Size() {
		return result, errors.New("hook receipt changed while reading")
	}
	// Exact keys also reject encoding/json case aliases and semantic duplicates.
	keys := map[string]bool{"event": false, "session_id": false, "session_home": false, "pid": false, "ppid": false, "executable": false, "executable_sha256": false, "input_sha256": false, "input_write_error": false, "outside_write_error": false, "config_write_error": false}
	dec := json.NewDecoder(bytes.NewReader(b))
	token, e := dec.Token()
	if e != nil || token != json.Delim('{') {
		return result, errors.New("hook receipt JSON object required")
	}
	for dec.More() {
		token, e = dec.Token()
		key, ok := token.(string)
		seen, known := keys[key]
		if e != nil || !ok || !known || seen {
			return result, errors.New("hook receipt unknown or duplicate field")
		}
		keys[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return result, errors.New("hook receipt invalid field")
		}
	}
	token, e = dec.Token()
	if e != nil || token != json.Delim('}') {
		return result, errors.New("hook receipt JSON incomplete")
	}
	if _, e = dec.Token(); e != io.EOF {
		return result, errors.New("hook receipt trailing JSON")
	}
	for _, seen := range keys {
		if !seen {
			return result, errors.New("hook receipt incomplete proof")
		}
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&result.Receipt) != nil {
		return result, errors.New("hook receipt field type")
	}
	r := result.Receipt
	if r.Event != "SessionStart" || len(r.SessionID) < 1 || len(r.SessionID) > 256 || strings.TrimSpace(r.SessionID) != r.SessionID || strings.IndexFunc(r.SessionID, func(c rune) bool { return c < 32 || c == 127 }) >= 0 || r.SessionHome != want.SessionHome || r.PID <= 1 || r.PPID <= 1 || r.PID == r.PPID || r.Executable != want.Executable || r.ExecutableSHA256 != want.ExecutableSHA256 || r.InputSHA256 != want.InputSHA256 || r.InputWriteError != "permission-denied" || r.OutsideWriteError != "permission-denied" || r.ConfigWriteError != "permission-denied" {
		return devinHookReceiptSnapshot{}, errors.New("hook receipt proof mismatch")
	}
	if verifyProcess != nil {
		if e = verifyProcess(r.PID, r.PPID); e != nil {
			return devinHookReceiptSnapshot{}, errors.New("independent hook process verification failed")
		}
		result.ProcessVerified = true
	}
	result.info = after
	result.digest = sha256.Sum256(b)
	return result, nil
}

// Retain first until after independent settlement but before Session cleanup.
// Same-byte replacement fails; vendor SessionID must remain unchanged.
func verifyDevinHookReceiptUnchanged(path string, want devinHookReceiptExpected, first devinHookReceiptSnapshot) error {
	if first.info == nil {
		return errors.New("first hook receipt snapshot absent")
	}
	final, e := readDevinHookReceipt(path, want, nil)
	if e != nil {
		return e
	}
	if !os.SameFile(first.info, final.info) || first.info.Mode() != final.info.Mode() || first.info.Size() != final.info.Size() || !first.info.ModTime().Equal(final.info.ModTime()) || first.digest != final.digest || first.Receipt != final.Receipt {
		return errors.New("hook receipt identity or bytes changed")
	}
	return nil
}

func TestDevinHookReceiptIntegrity(t *testing.T) {
	home, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	exe := sha256.Sum256([]byte("independent helper"))
	input := sha256.Sum256([]byte("independent input"))
	want := devinHookReceiptExpected{home, filepath.Join(home, "hook-witness"), hex.EncodeToString(exe[:]), hex.EncodeToString(input[:])}
	good := devinHookReceipt{"SessionStart", "vendor-session", home, 41, 40, want.Executable, want.ExecutableSHA256, want.InputSHA256, "permission-denied", "permission-denied", "permission-denied"}
	body, e := json.Marshal(good)
	if e != nil {
		t.Fatal(e)
	}
	path := func(t *testing.T) string {
		t.Helper()
		return filepath.Join(home, t.Name()[strings.LastIndex(t.Name(), "/")+1:])
	}
	put := func(t *testing.T, p string, b []byte) {
		t.Helper()
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Run("complete", func(t *testing.T) {
		p := path(t)
		put(t, p, body)
		called := false
		first, e := readDevinHookReceipt(p, want, func(pid, ppid int) error {
			called = true
			if pid != 41 || ppid != 40 {
				return errors.New("unexpected")
			}
			return nil
		})
		if e != nil || !called || !first.ProcessVerified {
			t.Fatal("verifier not used", e)
		}
		if e = verifyDevinHookReceiptUnchanged(p, want, first); e != nil {
			t.Fatal(e)
		}
		plain, e := readDevinHookReceipt(p, want, nil)
		if e != nil || plain.ProcessVerified {
			t.Fatal("invented process proof")
		}
		if _, e = readDevinHookReceipt(p, want, func(int, int) error { return errors.New("private path/token") }); e == nil || strings.Contains(e.Error(), "private") {
			t.Fatal("unsanitized verifier failure")
		}
	})
	for name, b := range map[string][]byte{
		"partial": body[:len(body)-1], "oversized": bytes.Repeat([]byte(" "), 4097), "unknown": append(append([]byte{}, body[:len(body)-1]...), []byte(`,"extra":true}`)...), "duplicate": append(append([]byte{}, body[:len(body)-1]...), []byte(`,"event":"SessionStart"}`)...), "case-alias": bytes.Replace(body, []byte(`"event"`), []byte(`"Event"`), 1), "null": bytes.Replace(body, []byte(`"pid":41`), []byte(`"pid":null`), 1), "fractional": bytes.Replace(body, []byte(`"pid":41`), []byte(`"pid":41.5`), 1), "incomplete": bytes.Replace(body, []byte(`,"config_write_error":"permission-denied"`), nil, 1), "wrong-denial": bytes.Replace(body, []byte(`"input_write_error":"permission-denied"`), []byte(`"input_write_error":"other-error"`), 1), "trailing": append(append([]byte{}, body...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			p := path(t)
			put(t, p, b)
			if _, e := readDevinHookReceipt(p, want, nil); e == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		p := path(t)
		target := p + "-target"
		put(t, target, body)
		if e := os.Symlink(target, p); e != nil {
			t.Fatal(e)
		}
		if _, e := readDevinHookReceipt(p, want, nil); e == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		p := path(t)
		if e := unix.Mkfifo(p, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readDevinHookReceipt(p, want, nil); e == nil {
			t.Fatal("FIFO accepted")
		}
	})
	t.Run("replacement", func(t *testing.T) {
		p := path(t)
		put(t, p, body)
		first, e := readDevinHookReceipt(p, want, nil)
		if e != nil {
			t.Fatal(e)
		}
		replacement := p + "-new"
		put(t, replacement, body)
		if e = os.Rename(replacement, p); e != nil {
			t.Fatal(e)
		}
		if verifyDevinHookReceiptUnchanged(p, want, first) == nil {
			t.Fatal("same-byte replacement accepted")
		}
	})
	t.Run("mutation", func(t *testing.T) {
		p := path(t)
		put(t, p, body)
		first, e := readDevinHookReceipt(p, want, nil)
		if e != nil {
			t.Fatal(e)
		}
		put(t, p, bytes.Replace(body, []byte("vendor-session"), []byte("vendor-changed"), 1))
		if verifyDevinHookReceiptUnchanged(p, want, first) == nil {
			t.Fatal("vendor identity changed")
		}
	})
	t.Run("digest-only", func(t *testing.T) {
		p := path(t)
		firstBytes := append([]byte(" "), body...)
		put(t, p, firstBytes)
		first, e := readDevinHookReceipt(p, want, nil)
		if e != nil {
			t.Fatal(e)
		}
		changed := append([]byte("\n"), body...)
		put(t, p, changed)
		if e = os.Chtimes(p, first.info.ModTime(), first.info.ModTime()); e != nil {
			t.Fatal(e)
		}
		if verifyDevinHookReceiptUnchanged(p, want, first) == nil {
			t.Fatal("same identity/size/mtime/meaning changed digest accepted")
		}
	})
	t.Run("mode-change", func(t *testing.T) {
		p := path(t)
		put(t, p, body)
		first, e := readDevinHookReceipt(p, want, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.Chmod(p, 0644); e != nil {
			t.Fatal(e)
		}
		if verifyDevinHookReceiptUnchanged(p, want, first) == nil {
			t.Fatal("mode change accepted")
		}
	})
	t.Run("ancestor-symlink", func(t *testing.T) {
		dir := path(t)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		put(t, filepath.Join(dir, "receipt"), body)
		alias := dir + "-alias"
		if e := os.Symlink(dir, alias); e != nil {
			t.Fatal(e)
		}
		if _, e := readDevinHookReceipt(filepath.Join(alias, "receipt"), want, nil); e == nil {
			t.Fatal("ancestor symlink accepted")
		}
	})
	t.Run("expectations", func(t *testing.T) {
		p := path(t)
		put(t, p, body)
		bad := want
		bad.InputSHA256 = ""
		if _, e := readDevinHookReceipt(p, bad, nil); e == nil {
			t.Fatal("missing expectation accepted")
		}
		bad = want
		bad.ExecutableSHA256 = strings.Repeat("0", 64)
		if _, e := readDevinHookReceipt(p, bad, nil); e == nil {
			t.Fatal("wrong executable accepted")
		}
	})
}

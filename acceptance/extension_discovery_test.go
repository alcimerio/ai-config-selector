package acceptance_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const discoveryOutputLimit = 64 << 10
const discoveryCodexArchiveSHA = "ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405"

// This fixed assessment capture never includes target output in diagnostics.
// Overflow is latched even when a target ignores the returned write error.
type discoveryCapture struct {
	mu       sync.Mutex
	body     []byte
	overflow bool
}

func (c *discoveryCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.body)+len(p) > discoveryOutputLimit {
		c.overflow = true
		return 0, errors.New("discovery output bound")
	}
	c.body = append(c.body, p...)
	return len(p), nil
}
func (c *discoveryCapture) bytes() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow {
		return nil, errors.New("discovery output bound")
	}
	return append([]byte(nil), c.body...), nil
}

// Static counterpart of the existing locked Codex native helper. Intentionally
// does not reuse that helper's uncontained --version subprocess.
func verifyDiscoveryCodex(archive, target string) error {
	f, e := os.Open(archive)
	if e != nil {
		return errors.New("Codex archive unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("Codex archive bounds")
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, (512<<20)+1)); e != nil || hex.EncodeToString(h.Sum(nil)) != discoveryCodexArchiveSHA {
		return errors.New("Codex archive lock")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return e
	}
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 600<<20))
	header, e := tr.Next()
	if e != nil || header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != "codex-aarch64-apple-darwin" || header.Size < 1 || header.Size > 512<<20 {
		return errors.New("Codex archive member")
	}
	mh := sha256.New()
	if _, e = io.Copy(mh, tr); e != nil {
		return e
	}
	if _, e = tr.Next(); e != io.EOF {
		return errors.New("Codex archive ambiguity")
	}
	actual, e := devinHookFileDigest(target, 512<<20)
	if e != nil || actual != hex.EncodeToString(mh.Sum(nil)) {
		return errors.New("Codex installed member mismatch")
	}
	return nil
}
func discoveryWrite(path string, body []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(body)
	return errors.Join(e, f.Close())
}
func seedDiscoveryPlugin(root string, codex bool) error {
	path := filepath.Join(root, ".devin-plugin", "plugin.json")
	body := []byte(`{"name":"acs-local","version":"1.0.0","description":"Synthetic local assessment"}`)
	if codex {
		path = filepath.Join(root, "plugin.json")
		body = []byte(`{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"acs-local","version":"1.0.0"}`)
	}
	if e := discoveryWrite(path, body); e != nil {
		return e
	}
	return discoveryWrite(filepath.Join(root, "skills", "receipt", "SKILL.md"), []byte("---\nname: receipt\ndescription: Synthetic discovery only\n---\nACS_DISCOVERY_ONLY\n"))
}
func seedDiscoveryCatalog(root string) error {
	// Pinned marketplace.rs650–692 resolves ./ paths against the catalog root,
	// not against .agents/plugins. No remote or dependency source is included.
	if e := discoveryWrite(filepath.Join(root, ".agents", "plugins", "marketplace.json"), []byte(`{"name":"acs-assessment","plugins":[{"name":"acs-local","source":{"source":"local","path":"./plugins/acs-local"}}]}`)); e != nil {
		return e
	}
	return seedDiscoveryPlugin(filepath.Join(root, "plugins", "acs-local"), true)
}
func discoveryJSON(body []byte) (any, error) {
	var v any
	d := json.NewDecoder(bytes.NewReader(body))
	if e := d.Decode(&v); e != nil {
		return nil, errors.New("discovery response JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("discovery trailing JSON")
	}
	return v, nil
}

// Exact value matching, never stdout substring matching. Shape-specific checks
// must additionally validate the pinned response's identity/installed fields.
func discoveryContainsValue(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case []any:
		for _, v := range x {
			if discoveryContainsValue(v, want) {
				return true
			}
		}
	case map[string]any:
		for _, v := range x {
			if discoveryContainsValue(v, want) {
				return true
			}
		}
	}
	return false
}
func TestDiscoveryFixedFixturesAndBounds(t *testing.T) {
	root := t.TempDir()
	if e := seedDiscoveryCatalog(root); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, ".agents", "plugins", "marketplace.json"))
	if e != nil {
		t.Fatal(e)
	}
	v, e := discoveryJSON(b)
	if e != nil || !discoveryContainsValue(v, "./plugins/acs-local") {
		t.Fatal("catalog path contract", e)
	}
	var c discoveryCapture
	if _, e = c.Write(bytes.Repeat([]byte("x"), discoveryOutputLimit)); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write([]byte("x")); e == nil {
		t.Fatal("overflow accepted")
	}
	if _, e = c.bytes(); e == nil {
		t.Fatal("overflow not latched")
	}
	if _, e = discoveryJSON([]byte(`{} {}`)); e == nil {
		t.Fatal("trailing response accepted")
	}
	if discoveryContainsValue(map[string]any{"name": "not-acs-local"}, "acs-local") {
		t.Fatal("substring accepted")
	}
}

func checkDiscoveryPluginList(t *testing.T, b []byte, installed bool) {
	t.Helper()
	var list struct {
		Installed, Available []struct {
			Name            string
			MarketplaceName string
			Installed       bool
			Enabled         bool
		}
	}
	if json.Unmarshal(b, &list) != nil {
		t.Fatal("plugin inventory JSON")
	}
	entries := list.Available
	if installed {
		entries = list.Installed
	}
	if len(entries) != 1 || entries[0].Name != "acs-local" || entries[0].MarketplaceName != "acs-assessment" || entries[0].Installed != installed {
		t.Fatal("plugin inventory identity/state")
	}
	if installed && (!entries[0].Enabled || len(list.Available) != 0) {
		t.Fatal("plugin not enabled")
	}
}
func discoveryHasToken(b []byte, want string) bool {
	for _, s := range strings.FieldsFunc(string(b), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') }) {
		if s == want {
			return true
		}
	}
	return false
}

// No thread/start or turn/start is sent: listing cannot count as execution.
type discoveryWire struct {
	mu      sync.Mutex
	capture discoveryCapture
	pending []byte
	lines   chan []byte
	failure bool
}

func (w *discoveryWire) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, e := w.capture.Write(p)
	if e != nil {
		return n, e
	}
	w.pending = append(w.pending, p...)
	for {
		at := bytes.IndexByte(w.pending, '\n')
		if at < 0 {
			break
		}
		line := append([]byte(nil), w.pending[:at]...)
		w.pending = w.pending[at+1:]
		select {
		case w.lines <- line:
		default:
			w.failure = true
			return 0, errors.New("discovery notification cap")
		}
	}
	return n, nil
}
func (w *discoveryWire) response(ctx context.Context, id int) (json.RawMessage, error) {
	for {
		select {
		case b := <-w.lines:
			var r struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(b, &r) != nil {
				return nil, errors.New("discovery wire JSON")
			}
			if r.ID == nil {
				continue
			}
			if *r.ID != id || len(r.Error) != 0 || len(r.Result) == 0 {
				return nil, errors.New("discovery response correlation")
			}
			return r.Result, nil
		case <-ctx.Done():
			return nil, errors.New("discovery wire deadline")
		}
	}
}

func checkDiscoveryHooks(b []byte, workspace, source, command string) error {
	var response struct {
		Data []struct {
			Cwd   string
			Hooks []struct {
				EventName, HandlerType, Command, SourcePath, TrustStatus, CurrentHash string
				TimeoutSec                                                            int
			}
			Warnings []json.RawMessage
			Errors   []json.RawMessage
		}
	}
	if json.Unmarshal(b, &response) != nil || len(response.Data) != 1 {
		return errors.New("hook discovery result shape")
	}
	d := response.Data[0]
	if d.Cwd != workspace || len(d.Hooks) != 1 || len(d.Warnings) != 0 || len(d.Errors) != 0 {
		return errors.New("hook discovery inventory")
	}
	h := d.Hooks[0]
	if h.SourcePath != source || h.Command != command || h.HandlerType != "command" || h.EventName != "sessionStart" || h.TimeoutSec != 1 || h.TrustStatus != "untrusted" || !strings.HasPrefix(h.CurrentHash, "sha256:") || !validDevinHookDigest(strings.TrimPrefix(h.CurrentHash, "sha256:")) {
		return errors.New("hook discovery fields")
	}
	return nil
}

func keepDiscoveryFixtures(t *testing.T, paths ...string) {
	t.Helper()
	type entry struct {
		path, digest string
		info         os.FileInfo
	}
	var entries []entry
	for _, p := range paths {
		h, e := devinHookFileDigest(p, 65536)
		if e != nil {
			t.Fatal("fixture initial digest")
		}
		i, e := os.Lstat(p)
		if e != nil {
			t.Fatal("fixture initial identity")
		}
		entries = append(entries, entry{p, h, i})
	}
	t.Cleanup(func() {
		for _, item := range entries {
			h, e := devinHookFileDigest(item.path, 65536)
			i, statErr := os.Lstat(item.path)
			if e != nil || statErr != nil || h != item.digest || !os.SameFile(item.info, i) || item.info.Mode() != i.Mode() || item.info.Size() != i.Size() || !item.info.ModTime().Equal(i.ModTime()) {
				t.Error("discovery input fixture changed")
			}
		}
	})
}
func TestDiscoveryActualWireAndHookValidation(t *testing.T) {
	good := []byte(`{"data":[{"cwd":"/workspace","hooks":[{"eventName":"sessionStart","handlerType":"command","command":"fixed","sourcePath":"/home/.codex/hooks.json","timeoutSec":1,"trustStatus":"untrusted","currentHash":"sha256:abc"}],"warnings":[],"errors":[]}]}`)
	good = bytes.Replace(good, []byte("sha256:abc"), []byte("sha256:"+strings.Repeat("a", 64)), 1)
	if e := checkDiscoveryHooks(good, "/workspace", "/home/.codex/hooks.json", "fixed"); e != nil {
		t.Fatal(e)
	}
	for _, pair := range [][2]string{{"sessionStart", "session_start"}, {"untrusted", "trusted"}, {"fixed", "other"}, {"/workspace", "/other"}, {`"errors":[]`, `"errors":[{}]`}} {
		b := bytes.Replace(good, []byte(pair[0]), []byte(pair[1]), 1)
		if e := checkDiscoveryHooks(b, "/workspace", "/home/.codex/hooks.json", "fixed"); e == nil {
			t.Fatal("bad hook evidence accepted")
		}
	}
	w := &discoveryWire{lines: make(chan []byte, 32)}
	for _, part := range []string{`{"method":"notice"}` + "\n" + `{"id":`, `2,"result":{"data":[]}}` + "\n"} {
		if _, e := w.Write([]byte(part)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := w.response(context.Background(), 2); e != nil {
		t.Fatal(e)
	}
	bad := &discoveryWire{lines: make(chan []byte, 32)}
	_, _ = bad.Write([]byte("{\"id\":3,\"result\":{}}\n"))
	if _, e := bad.response(context.Background(), 2); e == nil {
		t.Fatal("uncorrelated response accepted")
	}
	flood := &discoveryWire{lines: make(chan []byte, 1)}
	if _, e := flood.Write([]byte("{}\n{}\n")); e == nil || !flood.failure {
		t.Fatal("notification budget not enforced")
	}
}

var errDiscoveryTimeout = errors.New("discovery command deadline")
var errDiscoveryCleanup = errors.New("discovery cleanup unproven")
var errDiscoveryCapture = errors.New("discovery output capture failed")

func discoveryFailureClass(err error) (string, int) {
	switch {
	case errors.Is(err, errDiscoveryTimeout):
		return "timeout", -1
	case errors.Is(err, errDiscoveryCleanup):
		return "cleanup", -1
	case errors.Is(err, errDiscoveryCapture):
		return "capture", -1
	}
	var boundary *launch.SandboxError
	if errors.As(err, &boundary) {
		return "boundary", -1
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "target-exit", exit.ExitCode()
	}
	return "setup", -1
}
func discoveryDevinEnvironment(endpoint string) (*environmentresource.Lease, error) {
	host, port, e := net.SplitHostPort(endpoint)
	if e != nil || host != "127.0.0.1" {
		return nil, errors.New("endpoint shape")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, errors.New("endpoint port")
	}
	names := []string{"WINDSURF_API_SERVER_URL", "CHISEL_MOCK_BACKEND_ADDR"}
	intents := make([]environmentresource.Intent, 0, 2)
	for _, name := range names {
		intents = append(intents, environmentresource.Intent{ID: strings.ToLower(name), Destination: name, Scope: "attached-process-tree", SourceKind: "host-environment", SourceName: name, Classification: "non-secret", Required: true})
	}
	return environmentresource.Resolve(intents, func(name string) (string, bool) { return "http://" + endpoint, name == names[0] || name == names[1] })
}
func discoveryInstalledDirectory(home, path string) (os.FileInfo, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("installed plugin path not absolute")
	}
	root, e := filepath.EvalSymlinks(home)
	if e != nil {
		return nil, errors.New("installed plugin root unavailable")
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil {
		return nil, errors.New("installed plugin path unavailable")
	}
	rel, e := filepath.Rel(root, canonical)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return nil, errors.New("installed plugin escapes Session HOME")
	}
	info, e := os.Stat(canonical)
	if e != nil || !info.IsDir() {
		return nil, errors.New("installed plugin is not a directory")
	}
	return info, nil
}
func discoveryTokenCount(b []byte, want string) int {
	n := 0
	for _, token := range strings.FieldsFunc(string(b), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') }) {
		if token == want {
			n++
		}
	}
	return n
}
func verifyDiscoveryDevinInventory(before, after []byte) error {
	if discoveryTokenCount(before, "acs-local") != 1 || discoveryTokenCount(after, "acs-local") != 1 || discoveryHasToken(after, "invalid-package") || !bytes.Equal(before, after) {
		return errors.New("Devin plugin inventory changed after rejected install")
	}
	return nil
}
func TestDiscoveryRevisionGuards(t *testing.T) {
	lease, e := discoveryDevinEnvironment("127.0.0.1:12345")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Release()
	var frame bytes.Buffer
	if e = lease.WriteFrame(&frame); e != nil {
		t.Fatal(e)
	}
	env, e := environmentresource.ReadFrame(&frame, nil)
	if e != nil || len(env) != 2 {
		t.Fatal("endpoint frame", e)
	}
	want := map[string]bool{"WINDSURF_API_SERVER_URL=http://127.0.0.1:12345": true, "CHISEL_MOCK_BACKEND_ADDR=http://127.0.0.1:12345": true}
	for _, v := range env {
		if !want[v] {
			t.Fatal("unexpected endpoint projection")
		}
		delete(want, v)
	}
	if len(want) != 0 {
		t.Fatal("missing endpoint override")
	}
	for _, bad := range []string{"example.com:12345", "127.0.0.1:0", "127.0.0.1:65536", "http://127.0.0.1:12345"} {
		if l, e := discoveryDevinEnvironment(bad); e == nil {
			l.Release()
			t.Fatal("invalid origin accepted")
		}
	}
	home := t.TempDir()
	inside := filepath.Join(home, "installed")
	if e = os.Mkdir(inside, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = discoveryInstalledDirectory(home, inside); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	alias := filepath.Join(home, "escape")
	if e = os.Symlink(outside, alias); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{alias, home, filepath.Join(home, "missing"), "relative"} {
		if _, e = discoveryInstalledDirectory(home, bad); e == nil {
			t.Fatal("invalid installed location accepted")
		}
	}
	baseline := []byte("acs-local 1.0.0\n")
	if e = verifyDiscoveryDevinInventory(baseline, baseline); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{[]byte("acs-local 1.0.0\ninvalid-package\n"), []byte("other 1.0.0\n"), []byte("acs-local 2.0.0\n"), []byte("acs-local acs-local\n")} {
		if verifyDiscoveryDevinInventory(baseline, bad) == nil {
			t.Fatal("changed inventory accepted")
		}
	}
	for _, test := range []struct {
		err  error
		want string
	}{{errDiscoveryTimeout, "timeout"}, {errDiscoveryCleanup, "cleanup"}, {errDiscoveryCapture, "capture"}, {errors.New("private-path-and-token"), "setup"}} {
		label, code := discoveryFailureClass(test.err)
		if label != test.want || code != -1 || strings.Contains(label, "private") {
			t.Fatal("diagnostic classification")
		}
	}
}

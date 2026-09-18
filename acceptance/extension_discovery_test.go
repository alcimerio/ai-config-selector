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
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

// Diagnostic labels are fixed vocabulary. Never render an error, output excerpt,
// path, URL, header or body supplied by a target.
func discoveryOutputFamily(body []byte) string {
	text := strings.ToLower(string(body))
	families := []struct {
		label   string
		needles []string
	}{
		{"config-load", []string{"failed to load configuration", "failed to parse user config", "error loading config"}},
		{"marketplace-manifest", []string{"marketplace root does not contain a supported manifest", "failed to parse marketplace"}},
		{"marketplace-write", []string{"failed to add marketplace", "failed to create marketplace install directory"}},
		{"permission", []string{"permission denied", "operation not permitted"}},
		{"auth", []string{"not logged in", "not signed in", "authentication required", "please log in", "please login"}},
		{"plugin-manifest", []string{"invalid plugin manifest", "failed to parse plugin", "no plugin manifest"}},
	}
	for _, family := range families {
		for _, needle := range family.needles {
			if strings.Contains(text, needle) {
				return family.label
			}
		}
	}
	if len(body) == 0 {
		return "empty"
	}
	return "other"
}
func discoveryCaptureDiagnostic(out, stderr *discoveryCapture) string {
	o, oe := out.bytes()
	e, ee := stderr.bytes()
	return fmt.Sprintf("stdout_bytes=%d stderr_bytes=%d stdout_overflow=%t stderr_overflow=%t stdout_family=%s stderr_family=%s", len(o), len(e), oe != nil, ee != nil, discoveryOutputFamily(o), discoveryOutputFamily(e))
}
func discoveryProtocolStage(stage int32) string {
	switch stage {
	case 0:
		return "prepare"
	case 1:
		return "start"
	case 2:
		return "initialize-write"
	case 3:
		return "initialize-response"
	case 4:
		return "list-write"
	case 5:
		return "list-response"
	case 6:
		return "stdin-close"
	}
	return "unknown"
}
func discoveryProtocolClass(err error) string {
	if err == nil {
		return "ok"
	}
	switch err.Error() {
	case "discovery wire JSON":
		return "invalid-json"
	case "discovery response correlation":
		return "response-correlation"
	case "discovery wire deadline", "discovery exchange deadline":
		return "response-deadline"
	}
	return "io-or-other"
}
func discoveryHookDiagnostic(stage int32, initialized, listed, deadline, waited bool, exchangeErr, waitErr, cleanupErr error, out, stderr *discoveryCapture) string {
	waitClass, exit := "not-run", 0
	if waited {
		waitClass = "ok"
	}
	if waitErr != nil {
		waitClass, exit = discoveryFailureClass(waitErr)
	}
	return fmt.Sprintf("stage=%s initialized=%t listed=%t deadline=%t exchange=%s wait=%s exit=%d cleanup_ok=%t %s", discoveryProtocolStage(stage), initialized, listed, deadline, discoveryProtocolClass(exchangeErr), waitClass, exit, cleanupErr == nil, discoveryCaptureDiagnostic(out, stderr))
}

// Record only the first eight requests; extra requests still fail the existing
// request cap. No attacker-controlled text survives this classifier.
type discoveryHTTPDiagnostics struct {
	mu       sync.Mutex
	recorded int
	methods  [3]int
	routes   [5]int
	query    int
}

func (d *discoveryHTTPDiagnostics) record(method, path string, hasQuery bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.recorded >= 8 {
		return
	}
	d.recorded++
	m := 2
	if method == "POST" {
		m = 0
	} else if method == "GET" {
		m = 1
	}
	d.methods[m]++
	r := 4
	switch path {
	case "/exa.seat_management_pb.SeatManagementService/GetCliTeamSettings":
		r = 0
	case "/exa.seat_management_pb.SeatManagementService/GetUserStatus":
		r = 1
	case "/exa.product_analytics_pb.ProductAnalyticsService/BatchRecordAnalyticsEvents":
		r = 2
	case devinModel:
		r = 3
	}
	d.routes[r]++
	if hasQuery {
		d.query++
	}
}
func (d *discoveryHTTPDiagnostics) summary() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("recorded=%d post=%d get=%d other_method=%d team=%d user_status=%d analytics=%d model=%d unknown_route=%d query_present=%d", d.recorded, d.methods[0], d.methods[1], d.methods[2], d.routes[0], d.routes[1], d.routes[2], d.routes[3], d.routes[4], d.query)
}
func TestDiscoverySafeDiagnostics(t *testing.T) {
	secret := "DO_NOT_PRINT_SECRET/private/sentinel"
	for _, tc := range []struct{ input, want string }{
		{"failed to load configuration: " + secret, "config-load"},
		{"failed to add marketplace '" + secret + "' to user config.toml", "marketplace-write"},
		{"Permission denied " + secret, "permission"}, {secret, "other"}, {"", "empty"},
	} {
		if got := discoveryOutputFamily([]byte(tc.input)); got != tc.want {
			t.Fatalf("family %q", got)
		}
	}
	var out, stderr discoveryCapture
	for _, chunk := range []string{"failed to load ", "configuration: ", secret[:9], secret[9:]} {
		_, _ = stderr.Write([]byte(chunk))
	}
	for _, tc := range []struct {
		stage                         int32
		initialized, listed, deadline bool
		exchange                      error
		want                          string
	}{
		{3, false, false, true, errors.New("discovery wire deadline"), "stage=initialize-response initialized=false listed=false deadline=true exchange=response-deadline"},
		{5, true, false, false, errors.New("discovery response correlation"), "stage=list-response initialized=true listed=false deadline=false exchange=response-correlation"},
		{6, true, true, true, nil, "stage=stdin-close initialized=true listed=true deadline=true exchange=ok"},
	} {
		got := discoveryHookDiagnostic(tc.stage, tc.initialized, tc.listed, tc.deadline, true, tc.exchange, errDiscoveryTimeout, errors.New(secret), &out, &stderr)
		if !strings.Contains(got, tc.want) || !strings.Contains(got, "cleanup_ok=false") || strings.Contains(got, secret) || strings.Contains(got, "/private/") {
			t.Fatal("diagnostic contract")
		}
	}
	if discoveryProtocolStage(999) != "unknown" || discoveryProtocolClass(errors.New(secret)) != "io-or-other" {
		t.Fatal("untrusted label")
	}
	var full discoveryCapture
	_, _ = full.Write(make([]byte, discoveryOutputLimit+1))
	if !strings.Contains(discoveryCaptureDiagnostic(&full, &stderr), "stdout_overflow=true") {
		t.Fatal("overflow lost")
	}
}
func TestDiscoveryHTTPDiagnosticBounds(t *testing.T) {
	var d discoveryHTTPDiagnostics
	d.record("POST", "/exa.seat_management_pb.SeatManagementService/GetCliTeamSettings", false)
	d.record("POST", "/exa.seat_management_pb.SeatManagementService/GetUserStatus", false)
	d.record("POST", "/exa.product_analytics_pb.ProductAnalyticsService/BatchRecordAnalyticsEvents", false)
	d.record("POST", devinModel, false)
	d.record("GET", "/secret", true)
	for i := 0; i < 20; i++ {
		d.record("SECRET_METHOD", "/SECRET_PATH", true)
	}
	want := "recorded=8 post=4 get=1 other_method=3 team=1 user_status=1 analytics=1 model=1 unknown_route=4 query_present=4"
	if got := d.summary(); got != want {
		t.Fatalf("fixed counts %s", got)
	}
}

// Same exact optional system probe as the production Codex executor; the
// generic boundary otherwise has no reason to grant this target-owned path.
func discoverySandboxRequests(kind string, request launch.ProcessRequest) (launch.SandboxCheck, launch.ProcessRequest) {
	if kind == "codex" {
		request.RuntimeProbePaths = []string{"/etc/codex/requirements.toml"}
	}
	check := launch.SandboxCheck{Workspace: request.Workspace, WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeProbePaths: append([]string(nil), request.RuntimeProbePaths...)}
	return check, request
}

const discoveryStatusResponse = "\x0a\x18\x2a\x12ACS_SYNTHETIC_TEAM\x30\x02\x50\x01"
const discoveryDefaultResponse = `{"code":"unimplemented","message":"ACS synthetic local driver"}`

// Five existing CLI operations; each admits at most two reviewed team replies,
// one status reply and one ancillary analytics refusal. No model requests.
type discoveryStartup struct {
	mu                                     sync.Mutex
	phase, phases, total, active, complete int
	counts                                 [3]int
	failure                                string
	diagnostic                             discoveryHTTPDiagnostics
}

func (d *discoveryStartup) failLocked(reason string) {
	if d.failure == "" {
		d.failure = reason
	}
}
func (d *discoveryStartup) begin(call int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != "" || d.phase != 0 || d.active != 0 || call != d.phases+1 || call > 5 {
		d.failLocked("phase-start")
		return errors.New("synthetic startup phase refused")
	}
	d.phase = call
	d.phases++
	d.counts = [3]int{}
	return nil
}
func (d *discoveryStartup) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.phase == 0 || d.active != 0 {
		d.failLocked("phase-settlement")
	}
	d.phase = 0
}
func (d *discoveryStartup) summary() (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("phases=%d total=%d complete=%d active=%d failure=%s %s", d.phases, d.total, d.complete, d.active, d.failure, d.diagnostic.summary()), d.failure != "" || d.active != 0
}
func (d *discoveryStartup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	d.mu.Lock()
	d.total++
	d.active++
	phase := d.phase
	d.diagnostic.record(r.Method, r.URL.Path, r.URL.RawQuery != "")
	valid := true
	if d.failure != "" || phase == 0 || d.total > 20 {
		d.failLocked("request-phase-or-total")
		valid = false
	}
	route := -1
	switch r.URL.Path {
	case devinSeat + "GetCliTeamSettings":
		route = 0
	case devinSeat + "GetUserStatus":
		route = 1
	case devinAnalytics:
		route = 2
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Header.Get("Content-Type") != "application/proto" || route < 0 {
		d.failLocked("request-contract")
		valid = false
	}
	if valid {
		d.counts[route]++
		limit := 1
		if route == 0 {
			limit = 2
		}
		if d.counts[route] > limit {
			d.failLocked("route-quota")
			valid = false
		}
	}
	d.mu.Unlock()

	status, content, data := 501, "application/json", []byte(discoveryDefaultResponse)
	if valid {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(body) == 0 || len(body) > 65536 {
			d.mu.Lock()
			d.failLocked("body-bound-or-read")
			d.mu.Unlock()
			valid = false
		} else if _, err = devinWire(body); err != nil {
			d.mu.Lock()
			d.failLocked("body-protobuf")
			d.mu.Unlock()
			valid = false
		}
	}
	if valid {
		switch route {
		case 0:
			status, content, data = 200, "application/proto", []byte{8, 1}
		case 1:
			status, content, data = 200, "application/proto", []byte(discoveryStatusResponse)
		}
	}
	d.mu.Lock()
	defer func() { d.active--; d.mu.Unlock() }()
	if d.phase != phase || d.failure != "" {
		d.failLocked("phase-changed")
		valid = false
		status, content, data = 501, "application/json", []byte(discoveryDefaultResponse)
	}
	// Keep the bounded response write in the admitted phase. Native server writes
	// have the existing one-second deadline; end cannot race a success publication.
	w.Header().Set("Content-Type", content)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	n, err := w.Write(data)
	if err != nil || n != len(data) {
		d.failLocked("reply-write")
	} else if valid {
		d.complete++
	}
}
func TestDiscoveryCodexRuntimeProbe(t *testing.T) {
	for _, kind := range []string{"codex", "devin"} {
		check, request := discoverySandboxRequests(kind, launch.ProcessRequest{Workspace: "/workspace", WorkspaceAccess: launch.WorkspaceAccessReadWrite, SessionsDirectory: "/sessions", Executable: "/target"})
		if check.Workspace != request.Workspace || check.Executable != request.Executable || check.SessionsDirectory != request.SessionsDirectory {
			t.Fatal("check/request mismatch")
		}
		if kind == "codex" {
			if len(check.RuntimeProbePaths) != 1 || len(request.RuntimeProbePaths) != 1 || check.RuntimeProbePaths[0] != "/etc/codex/requirements.toml" || request.RuntimeProbePaths[0] != "/etc/codex/requirements.toml" {
				t.Fatal("exact Codex probe missing")
			}
			check.RuntimeProbePaths[0] = "changed"
			if request.RuntimeProbePaths[0] != "/etc/codex/requirements.toml" {
				t.Fatal("probe alias")
			}
		} else if len(check.RuntimeProbePaths) != 0 || len(request.RuntimeProbePaths) != 0 {
			t.Fatal("probe leaked to Devin")
		}
	}
}
func discoveryStartupRequest(d *discoveryStartup, path string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://fixture"+path, body)
	r.Header.Set("Content-Type", "application/proto")
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w
}
func TestDiscoveryStartupExactReplies(t *testing.T) {
	h := sha256.Sum256([]byte(discoveryStatusResponse))
	if hex.EncodeToString(h[:]) != "15e81c3724477e95074913d5f0913da83b09730c932db589b72db999bccb66c2" {
		t.Fatal("reviewed status bytes changed")
	}
	var d discoveryStartup
	for call := 1; call <= 5; call++ {
		if err := d.begin(call); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			path    string
			status  int
			content string
			body    []byte
		}{
			{devinSeat + "GetCliTeamSettings", 200, "application/proto", []byte{8, 1}},
			{devinSeat + "GetCliTeamSettings", 200, "application/proto", []byte{8, 1}},
			{devinSeat + "GetUserStatus", 200, "application/proto", []byte(discoveryStatusResponse)},
			{devinAnalytics, 501, "application/json", []byte(discoveryDefaultResponse)},
		} {
			w := discoveryStartupRequest(&d, tc.path, bytes.NewReader([]byte{8, 1}))
			if w.Code != tc.status || w.Header().Get("Content-Type") != tc.content || !bytes.Equal(w.Body.Bytes(), tc.body) {
				t.Fatal("exact reply mismatch")
			}
		}
		d.end()
	}
	summary, failed := d.summary()
	if failed || !strings.Contains(summary, "phases=5 total=20 complete=20 active=0") {
		t.Fatal("bounded startup did not settle")
	}
	if d.begin(6) == nil {
		t.Fatal("extra command accepted")
	}
}

type discoveryErrorReader struct{}

func (discoveryErrorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_READ_ERROR") }

type discoveryFailWriter struct{ header http.Header }

func (w *discoveryFailWriter) Header() http.Header       { return w.header }
func (w *discoveryFailWriter) WriteHeader(int)           {}
func (w *discoveryFailWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_WRITE_ERROR") }
func TestDiscoveryStartupRefusals(t *testing.T) {
	for _, name := range []string{"before-phase", "method", "query", "empty-query", "encoded-path", "type", "unknown", "model", "empty", "oversize", "malformed", "read-error", "team-quota", "status-quota", "analytics-quota", "after-phase", "write-error"} {
		t.Run(name, func(t *testing.T) {
			var d discoveryStartup
			if name != "before-phase" {
				if e := d.begin(1); e != nil {
					t.Fatal(e)
				}
			}
			path := devinSeat + "GetCliTeamSettings"
			method := "POST"
			content := "application/proto"
			var body io.Reader = bytes.NewReader([]byte{8, 1})
			switch name {
			case "method":
				method = "GET"
			case "query":
				path += "?SECRET_QUERY"
			case "empty-query":
				path += "?"
			case "encoded-path":
				path = strings.Replace(path, "GetCli", "%47etCli", 1)
			case "type":
				content = "application/json"
			case "unknown":
				path = "/SECRET_PATH"
			case "model":
				path = devinModel
			case "empty":
				body = bytes.NewReader(nil)
			case "oversize":
				body = bytes.NewReader(make([]byte, 65537))
			case "malformed":
				body = bytes.NewReader([]byte{0xff})
			case "read-error":
				body = discoveryErrorReader{}
			case "team-quota":
				for i := 0; i < 2; i++ {
					discoveryStartupRequest(&d, path, bytes.NewReader([]byte{8, 1}))
				}
			case "status-quota":
				path = devinSeat + "GetUserStatus"
				discoveryStartupRequest(&d, path, bytes.NewReader([]byte{8, 1}))
			case "analytics-quota":
				path = devinAnalytics
				discoveryStartupRequest(&d, path, bytes.NewReader([]byte{8, 1}))
			case "after-phase":
				d.end()
			}
			r := httptest.NewRequest(method, "http://fixture"+path, body)
			r.Header.Set("Content-Type", content)
			if name == "write-error" {
				d.ServeHTTP(&discoveryFailWriter{http.Header{}}, r)
			} else {
				w := httptest.NewRecorder()
				d.ServeHTTP(w, r)
				if w.Code != 501 {
					t.Fatal("invalid request succeeded")
				}
			}
			summary, failed := d.summary()
			if !failed || strings.Contains(summary, "SECRET") || strings.Contains(summary, "PRIVATE") {
				t.Fatal("refusal/diagnostic contract")
			}
		})
	}
}

type discoveryGatedReader struct {
	ready, release chan struct{}
	read           bool
}

func (r *discoveryGatedReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	close(r.ready)
	<-r.release
	return copy(p, []byte{8, 1}), nil
}
func TestDiscoveryStartupPhaseCannotChangeDuringBody(t *testing.T) {
	var d discoveryStartup
	if e := d.begin(1); e != nil {
		t.Fatal(e)
	}
	r := &discoveryGatedReader{ready: make(chan struct{}), release: make(chan struct{})}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- discoveryStartupRequest(&d, devinSeat+"GetUserStatus", r) }()
	select {
	case <-r.ready:
	case <-time.After(time.Second):
		close(r.release)
		t.Fatal("body readiness deadline")
	}
	d.end()
	close(r.release)
	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-time.After(time.Second):
		t.Fatal("body completion deadline")
	}
	if w.Code != 501 {
		t.Fatal("late phase reply succeeded")
	}
	if summary, failed := d.summary(); !failed || !strings.Contains(summary, "complete=0 active=0") {
		t.Fatal("phase failure missing")
	}
}

type discoveryGatedWriter struct {
	*httptest.ResponseRecorder
	ready, release chan struct{}
}

func (w *discoveryGatedWriter) Write(p []byte) (int, error) {
	n, e := w.ResponseRecorder.Write(p)
	close(w.ready)
	<-w.release
	return n, e
}
func TestDiscoveryStartupReplyAndSettlementAreAtomic(t *testing.T) {
	var d discoveryStartup
	if e := d.begin(1); e != nil {
		t.Fatal(e)
	}
	w := &discoveryGatedWriter{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(w.release) }) }
	defer release()
	r := httptest.NewRequest("POST", "http://fixture"+devinSeat+"GetCliTeamSettings", bytes.NewReader([]byte{8, 1}))
	r.Header.Set("Content-Type", "application/proto")
	served := make(chan struct{})
	go func() { d.ServeHTTP(w, r); close(served) }()
	select {
	case <-w.ready:
	case <-time.After(time.Second):
		t.Fatal("reply readiness deadline")
	}
	ended := make(chan struct{})
	go func() { d.end(); close(ended) }()
	select {
	case <-ended:
		t.Fatal("phase ended during response write")
	case <-time.After(time.Millisecond):
	}
	release()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("reply completion deadline")
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("phase settlement deadline")
	}
	if summary, failed := d.summary(); failed || !strings.Contains(summary, "complete=1 active=0") {
		t.Fatal("completed reply was not atomically settled")
	}
}

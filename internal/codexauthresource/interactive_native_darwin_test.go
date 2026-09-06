//go:build darwin

package codexauthresource_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/creack/pty"
)

// TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity is the
// credential-free half of the interactive acceptance gate. ACS starts a
// test-only fixed trampoline, which immediately execs the checksum-locked real
// target and adds only a literal loopback ChatGPT endpoint after ACS's fixed
// arguments. It is intentionally reported separately from direct raw-target
// executor coverage.
func TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to use an isolated temporary Keychain")
	}
	candidate := os.Getenv("ACS_PROMOTED_BINARY")
	target := os.Getenv("ACS_TEST_CODEX_BINARY")
	archive := os.Getenv("ACS_TEST_CODEX_ARCHIVE")
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(target) || !filepath.IsAbs(archive) {
		t.Fatal("ACS_PROMOTED_BINARY, ACS_TEST_CODEX_BINARY and ACS_TEST_CODEX_ARCHIVE must be absolute")
	}
	assertLockedCodexIdentity(t, archive, target)
	codexauthresource.UseIsolatedTestKeychainForComposition(t)

	root := t.TempDir()
	home, workspace, tools := filepath.Join(root, "home"), filepath.Join(root, "workspace"), filepath.Join(root, "tools")
	for _, directory := range []string{home, workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeNativeSkill(t, filepath.Join(home, ".agents", "skills", "managed-proof"), "managed-proof", "ACS_MANAGED_SKILL_SENTINEL")
	writeNativeSkill(t, filepath.Join(workspace, ".agents", "skills", "project-proof"), "project-proof", "PROJECT_INHERITED_SKILL_SENTINEL")
	hostileMCPMarker := filepath.Join(workspace, "hostile-project-mcp-started")
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex", "config.toml"), []byte(
		"[mcp_servers.hostile]\ncommand = \"/bin/sh\"\nargs = [\"-c\", "+strconv.Quote("printf hostile > "+hostileMCPMarker)+"]\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	globalAuth := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("unrelated-global-auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	configureInstalledCandidateKeychainContext(t, home, tools)
	buildSyntheticLoginTarget(t, filepath.Join(tools, "codex"))
	if !t.Run("installed ACS synthetic login transaction", func(t *testing.T) {
		runInstalledSyntheticLogin(t, candidate, home, tools, workspace, "login-proof")
		assertInstalledIdentityVisible(t, candidate, home, tools, workspace, "login-proof")
	}) {
		t.FailNow()
	}
	writeNativeCodexProfile(t, home, "coding", "login-proof", "read-write")
	writeNativeCodexProfile(t, home, "readonly", "login-proof", "read-only")
	grantedTarget := filepath.Join(workspace, "locked-codex-target")
	copyLockedTarget(t, target, grantedTarget)
	outside, err := os.MkdirTemp("/tmp", "acs-codex-unrelated-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	outsideSecret, outsideWrite := filepath.Join(outside, "secret"), filepath.Join(outside, "write")
	if err := os.WriteFile(outsideSecret, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	isolationProbe := fmt.Sprintf(`; if cat %s >/dev/null 2>&1; then printf global-auth-read-bad; else printf global-auth-read-denied; fi; if cat %s >/dev/null 2>&1; then printf outside-read-bad; else printf outside-read-denied; fi; if printf bad > %s 2>/dev/null; then printf outside-write-bad; else printf outside-write-denied; fi; sleep 30 </dev/null >/dev/null 2>&1 & printf descendant-pid:%%s "$!"`, strconv.Quote(globalAuth), strconv.Quote(outsideSecret), strconv.Quote(outsideWrite))
	for _, test := range []struct {
		name, profile, command, marker string
		wantWrite                      bool
	}{
		{name: "coding write", profile: "coding", command: "printf codex-native-tool-ok > ./codex-native-write; printf codex-native-tool-output" + isolationProbe, marker: "codex-native-write", wantWrite: true},
		{name: "read-only denial", profile: "readonly", command: "printf forbidden > ./codex-native-readonly-write; printf codex-native-tool-output" + isolationProbe, marker: "codex-native-readonly-write", wantWrite: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNativeResponsesFixture(t, test.command, home)
			defer fixture.server.Close()
			trampoline := filepath.Join(tools, "codex")
			buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", trampoline)
			t.Logf("harness executable sha256=%s; locked target member sha256=%s", fileSHA256(t, trampoline), fileSHA256(t, grantedTarget))
			runInstalledCodexPTY(t, candidate, home, tools, workspace, test.profile, fixture)
			descendantPID := fixture.assert(t)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && syscall.Kill(descendantPID, 0) == nil {
				time.Sleep(20 * time.Millisecond)
			}
			if err := syscall.Kill(descendantPID, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("Codex tool descendant %d survived settlement: %v", descendantPID, err)
			}
			contents, err := os.ReadFile(filepath.Join(workspace, test.marker))
			if test.wantWrite && (err != nil || string(contents) != "codex-native-tool-ok") {
				t.Fatalf("real Codex shell tool result=%q err=%v", contents, err)
			}
			if !test.wantWrite && !os.IsNotExist(err) {
				t.Fatalf("read-only Codex wrote workspace marker: bytes=%q err=%v", contents, err)
			}
			assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
		})
	}
	if contents, err := os.ReadFile(globalAuth); err != nil || string(contents) != "unrelated-global-auth" {
		t.Fatal("interactive launch changed global Codex authentication state")
	}
	if _, err := os.Stat(outsideWrite); !os.IsNotExist(err) {
		t.Fatalf("interactive launch wrote unrelated host path: %v", err)
	}
	if _, err := os.Stat(hostileMCPMarker); !os.IsNotExist(err) {
		t.Fatalf("interactive launch started hostile project MCP configuration: %v", err)
	}
}

func runInstalledSyntheticLogin(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	command := exec.Command(candidate, "codex", "auth", "login", "--name", name)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var output nativeSafeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copyDone) }()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var runErr error
	timedOut := false
	settlementTimedOut := false
	select {
	case runErr = <-wait:
	case <-time.After(20 * time.Second):
		timedOut = true
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case runErr = <-wait:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			select {
			case runErr = <-wait:
			case <-time.After(5 * time.Second):
				settlementTimedOut = true
			}
		}
	}
	_ = master.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("installed ACS synthetic login capture did not drain")
	}
	if settlementTimedOut {
		t.Fatalf("installed ACS synthetic login process group did not settle after corrected Keychain selection; terminal=%q", output.String())
	}
	if timedOut {
		t.Fatalf("installed ACS synthetic login timed out after corrected Keychain selection; terminal=%q; settlement=%v", output.String(), runErr)
	}
	if runErr != nil {
		t.Fatalf("installed ACS synthetic login failed: %v; terminal=%q", runErr, output.String())
	}
	for _, witness := range []string{"synthetic-login-target:started", "synthetic-login-target:auth-written", `Stored Codex authentication identity "` + name + `".`} {
		if !strings.Contains(output.String(), witness) {
			t.Fatalf("installed ACS synthetic login omitted %q; terminal=%q", witness, output.String())
		}
	}
}

func configureInstalledCandidateKeychainContext(t *testing.T, home, tools string) {
	t.Helper()
	parentDefault, parentDefaultOK := queryNativeKeychainSelection(nil, "default-keychain")
	parentSearch, parentSearchOK := queryNativeKeychainSelection(nil, "list-keychains")
	if !parentDefaultOK || !parentSearchOK {
		t.Fatal("isolated parent Keychain selection is unavailable")
	}
	fixtureEnvironment := nativeCandidateEnvironment(home, tools)
	fixtureDefaultBefore, fixtureDefaultBeforeOK := queryNativeKeychainSelection(fixtureEnvironment, "default-keychain")
	fixtureSearchBefore, fixtureSearchBeforeOK := queryNativeKeychainSelection(fixtureEnvironment, "list-keychains")
	t.Logf(
		"synthetic HOME Keychain selection before setup: default-match=%t search-list-match=%t",
		fixtureDefaultBeforeOK && fixtureDefaultBefore == parentDefault,
		fixtureSearchBeforeOK && fixtureSearchBefore == parentSearch,
	)
	keychain := strings.Trim(strings.TrimSpace(parentDefault), `"`)
	if keychain == "" || !filepath.IsAbs(keychain) {
		t.Fatal("isolated default Keychain selection is unavailable")
	}
	if err := os.MkdirAll(filepath.Join(home, "Library", "Preferences"), 0o700); err != nil {
		t.Fatal("prepare synthetic HOME Keychain preferences")
	}
	for _, arguments := range [][]string{
		{"list-keychains", "-d", "user", "-s", keychain},
		{"default-keychain", "-d", "user", "-s", keychain},
	} {
		command := exec.Command("/usr/bin/security", arguments...)
		command.Env = fixtureEnvironment
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatal("configure synthetic HOME to use the disposable Keychain")
		}
	}
	fixtureDefaultAfter, fixtureDefaultAfterOK := queryNativeKeychainSelection(fixtureEnvironment, "default-keychain")
	fixtureSearchAfter, fixtureSearchAfterOK := queryNativeKeychainSelection(fixtureEnvironment, "list-keychains")
	defaultMatches := fixtureDefaultAfterOK && fixtureDefaultAfter == parentDefault
	searchMatches := fixtureSearchAfterOK && fixtureSearchAfter == parentSearch
	t.Logf("synthetic HOME Keychain selection after setup: default-match=%t search-list-match=%t", defaultMatches, searchMatches)
	if !defaultMatches || !searchMatches {
		t.Fatal("synthetic HOME did not select the disposable Keychain")
	}
}

func queryNativeKeychainSelection(environment []string, operation string) (string, bool) {
	command := exec.Command("/usr/bin/security", operation, "-d", "user")
	if environment != nil {
		command.Env = environment
	}
	output, err := command.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}

func nativeCandidateEnvironment(home, tools string) []string {
	return []string{"HOME=" + home, "PATH=" + tools + ":/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=xterm", "COLORTERM=truecolor"}
}

func assertInstalledIdentityVisible(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	command := exec.Command(candidate, "codex", "auth", "list")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed ACS cannot enumerate seeded synthetic identity: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), name) || !strings.Contains(string(output), "synthetic-workspace") {
		t.Fatalf("installed ACS did not enumerate the selected synthetic identity: output=%q", output)
	}
}

func runInstalledCodexPTY(t *testing.T, candidate, home, tools, workspace, profile string, fixture *nativeResponsesFixture) string {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(candidate, "codex", "--profile", profile)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var output nativeSafeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copyDone) }()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			select {
			case <-wait:
			case <-time.After(10 * time.Second):
				t.Error("PTY fixture did not reap the installed ACS process")
			}
		}
		_ = master.Close()
		select {
		case <-copyDone:
		case <-time.After(time.Second):
			t.Error("PTY fixture did not drain terminal capture")
		}
	}()
	select {
	case err := <-wait:
		finished = true
		t.Fatalf("installed ACS or locked target exited before interactive input: %v; terminal=%q", err, output.String())
	case <-time.After(1500 * time.Millisecond):
	}
	if !waitNativeCaptureStable(&output, 2*time.Second) {
		t.Fatalf("real Codex TUI did not reach a stable pre-resize frame; terminal=%q", output.String())
	}
	resizeOffset := output.Len()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 43, Cols: 117}); err != nil {
		t.Fatal(err)
	}
	size, err := pty.GetsizeFull(master)
	if err != nil || size.Rows != 43 || size.Cols != 117 {
		t.Fatalf("resized outer PTY geometry=%v err=%v", size, err)
	}
	if !waitNativeCaptureContainsAfter(&output, resizeOffset, "\x1b[1;43r", 2*time.Second) {
		t.Fatalf("real Codex TUI did not render the resized 43-row terminal geometry; terminal=%q", output.String())
	}
	// Emulate a real terminal paste and let Codex's 120ms paste-burst window
	// settle before sending the separately encoded enhanced Enter key.
	if _, err := master.Write([]byte("\x1b[200~Use the shell tool exactly once as requested by the fixture.\x1b[201~")); err != nil {
		t.Fatalf("write interactive input: %v; terminal=%q", err, output.String())
	}
	if !waitNativeCaptureStable(&output, 2*time.Second) {
		t.Fatalf("real Codex TUI did not settle the bracketed prompt paste; terminal=%q", output.String())
	}
	if _, err := master.Write([]byte("\x1b[13u")); err != nil {
		t.Fatalf("submit interactive input: %v; terminal=%q", err, output.String())
	}
	select {
	case <-fixture.completed:
	case err := <-wait:
		finished = true
		t.Fatalf("installed ACS or locked target exited before completing tool work: %v; terminal=%q", err, output.String())
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("real Codex did not complete two fixture requests; loopback=%s; terminal=%q", fixture.summary(), output.String())
	}
	time.Sleep(500 * time.Millisecond)
	_, _ = master.Write([]byte{3})
	time.Sleep(150 * time.Millisecond)
	_, _ = master.Write([]byte{3})
	select {
	case err := <-wait:
		finished = true
		if err != nil {
			t.Fatalf("installed ACS interactive Codex exit: %v; terminal=%q", err, output.String())
		}
	case <-time.After(15 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("interactive Codex did not terminate after PTY cancellation")
	}
	return output.String()
}

func waitNativeCaptureStable(capture *nativeSafeCapture, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	last := -1
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		length := capture.Len()
		if length != last {
			last = length
			stableSince = time.Now()
		} else if time.Since(stableSince) >= 150*time.Millisecond {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func waitNativeCaptureContainsAfter(capture *nativeSafeCapture, offset int, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		contents := capture.String()
		if offset <= len(contents) && strings.Contains(contents[offset:], needle) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

type nativeSafeCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (capture *nativeSafeCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Write(contents)
}

func (capture *nativeSafeCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String()
}

func (capture *nativeSafeCapture) Len() int {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Len()
}

type nativeResponsesFixture struct {
	server                *httptest.Server
	completed             chan struct{}
	mu                    sync.Mutex
	requests              int
	bodies                []string
	headers               []http.Header
	sessionObservationErr string
	observations          []nativeRequestObservation
	websocketFallbacks    int
	modelRequests         int
	protocolErr           string
}

type nativeRequestObservation struct {
	method, path                 string
	hasAuthorization, hasAccount bool
}

func newNativeResponsesFixture(t *testing.T, shellCommand, launcherHome string) *nativeResponsesFixture {
	t.Helper()
	fixture := &nativeResponsesFixture{completed: make(chan struct{})}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		fixture.observations = append(fixture.observations, nativeRequestObservation{
			method: request.Method, path: request.URL.Path,
			hasAuthorization: request.Header.Get("Authorization") != "",
			hasAccount:       request.Header.Get("ChatGPT-Account-ID") != "",
		})
		if fixture.protocolErr == "" && (request.Header.Get("Authorization") != "Bearer synthetic-access" || request.Header.Get("ChatGPT-Account-ID") != "synthetic-workspace") {
			fixture.protocolErr = "loopback request did not retain the exact named identity headers"
		}
		fixture.mu.Unlock()
		switch request.URL.Path {
		case "/backend-api/codex/models":
			if request.Method != http.MethodGet {
				fixture.rejectProtocol(response, "models endpoint used a non-GET method")
				return
			}
			fixture.mu.Lock()
			fixture.modelRequests++
			fixture.mu.Unlock()
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"models":[]}`)
			return
		case "/backend-api/codex/responses":
			if request.Method == http.MethodGet && strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
				fixture.mu.Lock()
				fixture.websocketFallbacks++
				fixture.mu.Unlock()
				response.Header().Set("Upgrade", "websocket")
				response.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			if request.Method != http.MethodPost {
				fixture.rejectProtocol(response, "Responses endpoint used neither WebSocket upgrade nor POST")
				return
			}
		case "/backend-api/wham/rate-limit-reset-credits", "/backend-api/wham/usage", "/backend-api/wham/settings/user":
			if request.Method != http.MethodGet {
				fixture.rejectProtocol(response, "usage endpoint used a non-GET method")
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{}`)
			return
		case "/backend-api/codex/analytics-events/events":
			if request.Method != http.MethodPost {
				fixture.rejectProtocol(response, "analytics endpoint used a non-POST method")
				return
			}
			response.WriteHeader(http.StatusNoContent)
			return
		default:
			fixture.rejectProtocol(response, "locked target requested an unexpected loopback path")
			return
		}
		body, err := decodeNativeResponsesBody(request.Body, request.Header.Get("Content-Encoding"))
		if err != nil {
			fixture.rejectProtocol(response, err.Error())
			return
		}
		fixture.mu.Lock()
		fixture.requests++
		index := fixture.requests
		fixture.bodies = append(fixture.bodies, body)
		fixture.headers = append(fixture.headers, request.Header.Clone())
		if index == 2 {
			fixture.sessionObservationErr = observeNativeSessionProjection(launcherHome)
		}
		fixture.mu.Unlock()
		response.Header().Set("Content-Type", "text/event-stream")
		if index == 1 {
			arguments, _ := json.Marshal(map[string]any{"command": shellCommand, "timeout_ms": 5000})
			writeSSE(response,
				map[string]any{"type": "response.created", "response": map[string]any{"id": "resp-1"}},
				map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "function_call", "call_id": "acs-call-1", "name": "shell_command", "arguments": string(arguments)}},
				completedEvent("resp-1"),
			)
			return
		}
		writeSSE(response,
			map[string]any{
				"type": "response.output_item.done",
				"item": map[string]any{
					"type": "message", "role": "assistant", "id": "msg-1",
					"content": []map[string]string{{"type": "output_text", "text": "fixture-complete"}},
				},
			},
			completedEvent("resp-2"),
		)
		if index == 2 {
			close(fixture.completed)
		}
	}))
	return fixture
}

func TestNativeResponsesFixtureSeparatesModelDiscoveryAndWebSocketFallback(t *testing.T) {
	fixture := newNativeResponsesFixture(t, "printf fixture", t.TempDir())
	defer fixture.server.Close()
	for _, test := range []struct {
		name, path, upgrade string
		wantStatus          int
		wantBody            string
	}{
		{name: "model discovery", path: "/backend-api/codex/models", wantStatus: http.StatusOK, wantBody: `{"models":[]}`},
		{name: "Responses WebSocket fallback", path: "/backend-api/codex/responses", upgrade: "websocket", wantStatus: http.StatusUpgradeRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, fixture.server.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer synthetic-access")
			request.Header.Set("ChatGPT-Account-ID", "synthetic-workspace")
			if test.upgrade != "" {
				request.Header.Set("Connection", "upgrade")
				request.Header.Set("Upgrade", test.upgrade)
			}
			response, err := fixture.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read fixture response = (%v, %v)", readErr, closeErr)
			}
			if response.StatusCode != test.wantStatus || (test.wantBody != "" && string(body) != test.wantBody) {
				t.Fatalf("fixture response = status %d body %q", response.StatusCode, body)
			}
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.protocolErr != "" || fixture.requests != 0 || fixture.modelRequests != 1 || fixture.websocketFallbacks != 1 {
		t.Fatalf("fixture routing = protocol=%q responses=%d models=%d fallbacks=%d", fixture.protocolErr, fixture.requests, fixture.modelRequests, fixture.websocketFallbacks)
	}
}

func (fixture *nativeResponsesFixture) rejectProtocol(response http.ResponseWriter, message string) {
	fixture.mu.Lock()
	if fixture.protocolErr == "" {
		fixture.protocolErr = message
	}
	fixture.mu.Unlock()
	http.Error(response, "fixture protocol rejected", http.StatusBadRequest)
}

func (fixture *nativeResponsesFixture) assert(t *testing.T) int {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.protocolErr != "" {
		t.Fatalf("fixture protocol error: %s; loopback=%s", fixture.protocolErr, fixture.summaryLocked())
	}
	if fixture.requests != 2 || len(fixture.bodies) != 2 {
		t.Fatalf("responses requests=%d; loopback=%s", fixture.requests, fixture.summaryLocked())
	}
	if fixture.websocketFallbacks != 1 {
		t.Fatalf("Responses WebSocket fallbacks=%d, want one; loopback=%s", fixture.websocketFallbacks, fixture.summaryLocked())
	}
	if fixture.modelRequests < 1 {
		t.Fatalf("authenticated model requests=%d, want at least one; loopback=%s", fixture.modelRequests, fixture.summaryLocked())
	}
	if fixture.sessionObservationErr != "" {
		t.Fatal(fixture.sessionObservationErr)
	}
	for _, headers := range fixture.headers {
		if headers.Get("Authorization") != "Bearer synthetic-access" || headers.Get("ChatGPT-Account-ID") != "synthetic-workspace" {
			t.Fatalf("named identity headers were not preserved: authorization=%q account=%q", headers.Get("Authorization"), headers.Get("ChatGPT-Account-ID"))
		}
	}
	for _, sentinel := range []string{"ACS_MANAGED_SKILL_SENTINEL", "PROJECT_INHERITED_SKILL_SENTINEL"} {
		if !strings.Contains(fixture.bodies[0], sentinel) {
			t.Fatalf("first request omitted Skill discovery sentinel %q", sentinel)
		}
	}
	toolOutput, err := nativeFunctionCallOutput(fixture.bodies[1], "acs-call-1")
	if err != nil {
		t.Fatalf("second request tool output: %v", err)
	}
	for _, sentinel := range []string{"Process exited with code 0", "codex-native-tool-output", "global-auth-read-denied", "outside-read-denied", "outside-write-denied"} {
		if !strings.Contains(toolOutput, sentinel) {
			t.Fatalf("second request omitted real shell result %q", sentinel)
		}
	}
	if strings.Contains(toolOutput, "global-auth-read-bad") || strings.Contains(toolOutput, "outside-read-bad") || strings.Contains(toolOutput, "outside-write-bad") {
		t.Fatal("matching function output reports an isolation escape")
	}
	match := regexp.MustCompile(`descendant-pid:(\d+)`).FindStringSubmatch(toolOutput)
	if len(match) != 2 {
		t.Fatal("second request omitted descendant process identity")
	}
	pid, err := strconv.Atoi(match[1])
	if err != nil || pid < 2 {
		t.Fatal("second request contained invalid descendant process identity")
	}
	return pid
}

func (fixture *nativeResponsesFixture) summaryLocked() string {
	parts := make([]string, 0, len(fixture.observations))
	for _, observation := range fixture.observations {
		parts = append(parts, fmt.Sprintf("%s %q auth=%t account=%t", observation.method, observation.path, observation.hasAuthorization, observation.hasAccount))
	}
	return strings.Join(parts, "; ")
}

func (fixture *nativeResponsesFixture) summary() string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.summaryLocked()
}

func observeNativeSessionProjection(launcherHome string) string {
	sessionHomes, err := filepath.Glob(filepath.Join(launcherHome, ".acs", "sessions", "session-*", "home"))
	if err != nil || len(sessionHomes) != 1 {
		return "live target did not retain exactly one private Session HOME"
	}
	sessionHome := sessionHomes[0]
	var rolloutPath string
	err = filepath.WalkDir(filepath.Join(sessionHome, ".codex", "sessions"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "rollout-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			rolloutPath = path
		}
		return nil
	})
	if err != nil || rolloutPath == "" {
		return "locked Codex private rollout was not observable while the Session was retained"
	}
	info, err := os.Stat(rolloutPath)
	if err != nil || info.Size() == 0 {
		return "locked Codex private rollout was empty or unavailable"
	}
	relativeRollout, err := filepath.Rel(sessionHome, rolloutPath)
	if err != nil {
		return "locked Codex private rollout path was invalid"
	}
	if _, err := os.Stat(filepath.Join(launcherHome, relativeRollout)); !os.IsNotExist(err) {
		return "locked Codex private rollout reached the launcher HOME"
	}
	return ""
}

func completedEvent(id string) map[string]any {
	return map[string]any{"type": "response.completed", "response": map[string]any{"id": id, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}}
}

func writeSSE(writer io.Writer, events ...map[string]any) {
	for _, event := range events {
		encoded, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(writer, "data: %s\n\n", encoded)
	}
}

func buildFixedCodexTrampoline(t *testing.T, target, baseURL, destination string) {
	t.Helper()
	source := filepath.Join(filepath.Dir(destination), "codex-trampoline.c")
	openAIOverride := fmt.Sprintf("openai_base_url=%q", baseURL+"/codex")
	chatGPTOverride := fmt.Sprintf("chatgpt_base_url=%q", baseURL)
	program := fmt.Sprintf(`#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char **next = calloc((size_t)argc + 5, sizeof(char *));
  if (!next) return 120;
  next[0] = %s;
  int version = 0;
  for (int i = 1; i < argc; i++) {
    next[i] = argv[i];
    if (strcmp(argv[i], "--version") == 0) version = 1;
	}
	if (!version) {
		next[argc] = "-c";
    next[argc + 1] = %s;
		next[argc + 2] = "-c";
		next[argc + 3] = %s;
	}
  execv(next[0], next);
  return 121;
}
`, strconv.Quote(target), strconv.Quote(openAIOverride), strconv.Quote(chatGPTOverride))
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.CreateTemp(filepath.Dir(destination), ".codex-trampoline-*")
	if err != nil {
		t.Fatal("prepare fixed Codex trampoline replacement")
	}
	replacementPath := replacement.Name()
	if err := replacement.Close(); err != nil {
		t.Fatal("prepare fixed Codex trampoline replacement")
	}
	defer os.Remove(replacementPath)
	if output, err := exec.Command("/usr/bin/clang", "-Os", source, "-o", replacementPath).CombinedOutput(); err != nil {
		t.Fatalf("compile fixed Codex trampoline: %v: %s", err, output)
	}
	if err := os.Chmod(replacementPath, 0o500); err != nil {
		t.Fatal("secure fixed Codex trampoline replacement")
	}
	if err := os.Rename(replacementPath, destination); err != nil {
		t.Fatal("atomically install fixed Codex trampoline replacement")
	}
}

func buildSyntheticLoginTarget(t *testing.T, destination string) {
	t.Helper()
	auth := compositionAuth(t)
	encoded := make([]string, len(auth))
	for index, value := range auth {
		encoded[index] = strconv.Itoa(int(value))
	}
	source := filepath.Join(t.TempDir(), "synthetic-login.c")
	program := `#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static const unsigned char auth[] = {` + strings.Join(encoded, ",") + `};
int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--version") == 0) { puts("codex-cli 0.149.1"); return 0; }
  }
  fputs("synthetic-login-target:started\n", stderr);
  fflush(stderr);
  const char *home = getenv("HOME");
  if (!home) return 10;
  char path[4096];
  if (snprintf(path, sizeof(path), "%s/.codex/auth.json", home) <= 0) return 11;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return 12;
  if (write(fd, auth, sizeof(auth)) != sizeof(auth) || fsync(fd) != 0 || close(fd) != 0) return 13;
  fputs("synthetic-login-target:auth-written\n", stderr);
  fflush(stderr);
  return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/clang", "-Os", source, "-o", destination).CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic login target: %v: %s", err, output)
	}
}

func writeNativeSkill(t *testing.T, directory, name, sentinel string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := "---\nname: " + name + "\ndescription: " + sentinel + "\n---\nUse this Skill only as native discovery evidence.\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeNativeCodexProfile(t *testing.T, home, profileName, authRef, access string) {
	t.Helper()
	profiles := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	document := `{"version":3,"name":` + strconv.Quote(profileName) + `,"common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"managed-proof"}]},"workspace":{"version":1,"selection":{"access":` + strconv.Quote(access) + `}}},"overlays":{"codex":{"version":1,"authRef":` + strconv.Quote(authRef) + `}}}`
	if err := os.WriteFile(filepath.Join(profiles, profileName+".json"), []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertLockedCodexIdentity(t *testing.T, archivePath, installedPath string) {
	t.Helper()
	want := map[string]string{"arm64": "ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405", "amd64": "85fe7a837eb739dd5e1cc59a9c95b7b682048e5aacdc261505bae768fb1288ef"}[runtime.GOARCH]
	if want == "" || fileSHA256(t, archivePath) != want {
		t.Fatal("Codex release archive does not match the reviewed architecture lock")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != map[string]string{"arm64": "codex-aarch64-apple-darwin", "amd64": "codex-x86_64-apple-darwin"}[runtime.GOARCH] {
		t.Fatal("locked archive member is not the expected regular target")
	}
	member, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("locked archive contains more than one member")
	}
	installed, err := os.ReadFile(installedPath)
	if err != nil || !bytes.Equal(member, installed) {
		t.Fatal("installed Codex bytes differ from the independently extracted locked member")
	}
	if output, err := exec.Command(installedPath, "--version").Output(); err != nil || strings.TrimSpace(string(output)) != "codex-cli 0.149.1" {
		t.Fatal("installed Codex member reports an unsupported version")
	}
}

func copyLockedTarget(t *testing.T, source, destination string) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, contents, 0o500); err != nil {
		t.Fatal(err)
	}
	if fileSHA256(t, source) != fileSHA256(t, destination) {
		t.Fatal("granted fixture target differs from installed locked target")
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func assertNoNativeSessions(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("interactive launch retained Session %q", entry.Name())
		}
	}
}

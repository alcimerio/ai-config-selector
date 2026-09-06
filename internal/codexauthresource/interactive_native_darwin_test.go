//go:build darwin

package codexauthresource_test

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
	"github.com/alcimerio/ai-config-selector/internal/session"
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
	globalAuth := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("unrelated-global-auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedNativeIdentity(t, home, workspace, "interactive")
	writeNativeCodexProfile(t, home, "coding", "interactive", "read-write")
	writeNativeCodexProfile(t, home, "readonly", "interactive", "read-only")
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
	isolationProbe := fmt.Sprintf(`; printf private > "$HOME/codex-private-proof" && printf private-ok; if cat %s >/dev/null 2>&1; then printf outside-read-bad; else printf outside-read-denied; fi; if printf bad > %s 2>/dev/null; then printf outside-write-bad; else printf outside-write-denied; fi; sleep 30 </dev/null >/dev/null 2>&1 & printf descendant-pid:%%s "$!"`, strconv.Quote(outsideSecret), strconv.Quote(outsideWrite))
	for _, test := range []struct {
		name, profile, command, marker string
		wantWrite                      bool
	}{
		{name: "coding write", profile: "coding", command: "printf codex-native-tool-ok > ./codex-native-write; printf codex-native-tool-output" + isolationProbe, marker: "codex-native-write", wantWrite: true},
		{name: "read-only denial", profile: "readonly", command: "printf forbidden > ./codex-native-readonly-write; printf codex-native-tool-output" + isolationProbe, marker: "codex-native-readonly-write", wantWrite: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNativeResponsesFixture(t, test.command)
			defer fixture.server.Close()
			trampoline := filepath.Join(tools, "codex")
			buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", trampoline)
			t.Logf("harness executable sha256=%s; locked target member sha256=%s", fileSHA256(t, trampoline), fileSHA256(t, grantedTarget))
			runInstalledCodexPTY(t, candidate, home, tools, workspace, test.profile, fixture.completed)
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
}

func runInstalledCodexPTY(t *testing.T, candidate, home, tools, workspace, profile string, completed <-chan struct{}) string {
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
	command.Env = []string{"HOME=" + home, "PATH=" + tools + ":/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=xterm", "COLORTERM=truecolor"}
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: int(terminal.Fd())}
	var output nativeSafeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copyDone) }()
	if err := command.Start(); err != nil {
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
	time.Sleep(1500 * time.Millisecond)
	if _, err := master.Write([]byte("Use the shell tool exactly once as requested by the fixture.\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("real Codex did not complete two fixture requests; terminal=%q", output.String())
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

type nativeResponsesFixture struct {
	server    *httptest.Server
	completed chan struct{}
	mu        sync.Mutex
	requests  int
	bodies    []string
	headers   []http.Header
}

func newNativeResponsesFixture(t *testing.T, shellCommand string) *nativeResponsesFixture {
	t.Helper()
	fixture := &nativeResponsesFixture{completed: make(chan struct{})}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/backend-api/codex/responses" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{}`)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		fixture.mu.Lock()
		fixture.requests++
		index := fixture.requests
		fixture.bodies = append(fixture.bodies, string(body))
		fixture.headers = append(fixture.headers, request.Header.Clone())
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

func (fixture *nativeResponsesFixture) assert(t *testing.T) int {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.requests != 2 || len(fixture.bodies) != 2 {
		t.Fatalf("responses requests=%d", fixture.requests)
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
	for _, sentinel := range []string{"acs-call-1", "codex-native-tool-output", "private-ok", "outside-read-denied", "outside-write-denied"} {
		if !strings.Contains(fixture.bodies[1], sentinel) {
			t.Fatalf("second request omitted real shell result %q", sentinel)
		}
	}
	if strings.Contains(fixture.bodies[1], "outside-read-bad") || strings.Contains(fixture.bodies[1], "outside-write-bad") {
		t.Fatal("second request omitted real shell function output")
	}
	match := regexp.MustCompile(`descendant-pid:(\d+)`).FindStringSubmatch(fixture.bodies[1])
	if len(match) != 2 {
		t.Fatal("second request omitted descendant process identity")
	}
	pid, err := strconv.Atoi(match[1])
	if err != nil || pid < 2 {
		t.Fatal("second request contained invalid descendant process identity")
	}
	return pid
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
	program := fmt.Sprintf(`#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char **next = calloc((size_t)argc + 3, sizeof(char *));
  if (!next) return 120;
  next[0] = %s;
  for (int i = 1; i < argc; i++) next[i] = argv[i];
  if (!(argc == 2 && strcmp(argv[1], "--version") == 0)) {
    next[argc] = "-c";
    next[argc + 1] = %s;
  }
  execv(next[0], next);
  return 121;
}
`, strconv.Quote(target), strconv.Quote(`chatgpt_base_url="`+baseURL+`"`))
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/clang", "-Os", source, "-o", destination).CombinedOutput(); err != nil {
		t.Fatalf("compile fixed Codex trampoline: %v: %s", err, output)
	}
}

func seedNativeIdentity(t *testing.T, home, workspace, name string) {
	t.Helper()
	locks, markers := filepath.Join(home, ".acs", "locks", "codex-auth"), filepath.Join(home, ".acs", "quarantine", "codex-auth")
	for _, directory := range []string{locks, markers} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := codexauthresource.New(locks, markers)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.AcquireLogin(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	created, err := session.Create(filepath.Join(home, ".acs", "seed-sessions"), workspace, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	authDirectory := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.Mkdir(authDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDirectory, "auth.json"), compositionAuth(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), created.RootDirectory()); err != nil {
		t.Fatal(err)
	}
	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := binding.DeleteMarkerAfterProjectionRemoval(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
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

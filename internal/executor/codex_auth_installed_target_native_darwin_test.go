//go:build darwin

package executor

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/creack/pty"
)

func TestNativeInstalledTargetContainedStatusWithoutCredentials(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to run the installed target in Seatbelt")
	}
	binary := os.Getenv("ACS_TEST_CODEX_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("ACS_TEST_CODEX_BINARY must name the absolute locked target")
	}
	if output, err := runInstalledTargetVersion(binary); err != nil || output != "codex-cli "+SupportedCodexVersion {
		t.Fatal("installed target did not report the supported version")
	}

	globalHome := t.TempDir()
	globalCodexHome := filepath.Join(globalHome, ".codex")
	if err := os.Mkdir(globalCodexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	globalSentinel := filepath.Join(globalCodexHome, "auth.json")
	if err := os.WriteFile(globalSentinel, []byte("global-auth-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", globalHome)

	root := t.TempDir()
	privateRoot := filepath.Join(root, "private")
	workspace := filepath.Join(root, "workspace")
	for _, directory := range []string{privateRoot, workspace} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	projectConfig := filepath.Join(workspace, ".codex")
	if err := os.Mkdir(projectConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectConfig, "config.toml"), []byte(
		"cli_auth_credentials_store = \"keyring\"\n"+
			"forced_login_method = \"api\"\n"+
			"forced_chatgpt_workspace_id = \"wrong-workspace\"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	name := CredentialRef("installed-target")
	auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
	metadata, err := validateAuthJSON(name, auth)
	if err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.records[name] = credentialRecord{Metadata: metadata, Auth: append([]byte(nil), auth...)}
	registry, err := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(filepath.Join(privateRoot, "locks")))
	if err != nil {
		t.Fatal(err)
	}
	registry.sessionsDirectory = filepath.Join(privateRoot, "sessions")
	registry.workingDirectory = workspace
	registryTestResources(registry).quarantine = newFileBindingQuarantine(filepath.Join(privateRoot, "quarantine"))
	registry.status = newCodexStatusRunner(codexLoginConfig{
		BinaryPath: binary, SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: registry.sessionsDirectory, WorkingDirectory: workspace, PrivateRoot: privateRoot,
	}, launch.NewProcessSandbox())

	status, err := registry.Status(context.Background(), string(name))
	if err != nil {
		for _, sentinel := range []string{"global-auth-sentinel", "access-secret", "refresh-secret", "synthetic-user"} {
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("contained status error exposed a sentinel")
			}
		}
		t.Fatalf("credential-free installed status failed: %v", err)
	}
	if status.Disposition != DiscardedProjection || provider.replaceCalls != 0 {
		t.Fatalf("installed status disposition = %q, replacements = %d", status.Disposition, provider.replaceCalls)
	}
	contents, err := os.ReadFile(globalSentinel)
	if err != nil || string(contents) != "global-auth-sentinel" {
		t.Fatal("installed status changed global authentication state")
	}
	assertNoSessionDirectories(t, registry.sessionsDirectory)
	if _, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), name); err != nil || exists {
		t.Fatalf("installed status quarantine = (%v, %v)", exists, err)
	}
}

// TestNativeDirectInstalledTargetInteractiveLifecycle deliberately does not
// use the loopback trampoline. It proves that the immutable raw target starts
// through the shared executor in a real PTY, survives a resize notification,
// accepts terminal cancellation, settles, and releases its named identity.
// Deterministic model/tool evidence remains the separate trampoline test.
func TestNativeDirectInstalledTargetInteractiveLifecycle(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to run the installed target in Seatbelt")
	}
	binary := os.Getenv("ACS_TEST_CODEX_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("ACS_TEST_CODEX_BINARY must name the absolute locked target")
	}
	if output, err := runInstalledTargetVersion(binary); err != nil || output != "codex-cli "+SupportedCodexVersion {
		t.Fatal("installed target did not report the supported version")
	}

	root := t.TempDir()
	privateRoot := filepath.Join(root, "private")
	workspace := filepath.Join(root, "workspace")
	for _, directory := range []string{privateRoot, workspace} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	name := CredentialRef("direct-interactive")
	auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
	metadata, err := validateAuthJSON(name, auth)
	if err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.records[name] = credentialRecord{Metadata: metadata, Auth: append([]byte(nil), auth...)}
	registry, err := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(filepath.Join(privateRoot, "locks")))
	if err != nil {
		t.Fatal(err)
	}
	registry.sessionsDirectory = filepath.Join(privateRoot, "sessions")
	registry.workingDirectory = workspace
	registryTestResources(registry).quarantine = newFileBindingQuarantine(filepath.Join(privateRoot, "quarantine"))
	registry.execution = newCodexExecutionRunner(codexLoginConfig{
		BinaryPath: binary, SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: registry.sessionsDirectory, WorkingDirectory: workspace, PrivateRoot: privateRoot,
	}, launch.NewProcessSandbox())
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{
		Recipe: authority.RecipeCodex, Executable: binary,
	}).WithAuthRef(string(name))

	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	var capture directNativeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&capture, master); close(copyDone) }()
	type result struct {
		code int
		err  error
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	finished := make(chan result, 1)
	go func() {
		code, runErr := registry.ExecuteCodex(runContext, CodexRequest{
			ResolvedPlan: &plan,
			Terminal:     launch.Terminal{Input: terminal, Output: terminal, ErrorOutput: terminal},
		})
		finished <- result{code: code, err: runErr}
	}()
	settled := false
	defer func() {
		if settled {
			return
		}
		cancelRun()
		_ = terminal.Close()
		_ = master.Close()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("raw target fixture did not settle after test failure")
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for capture.Len() == 0 && time.Now().Before(deadline) {
		select {
		case got := <-finished:
			settled = true
			t.Fatalf("raw target exited before interactive startup: (%d, %v), terminal=%q", got.code, got.err, capture.String())
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	if capture.Len() == 0 {
		t.Fatal("raw target produced no interactive terminal output")
	}
	if err := pty.Setsize(master, &pty.Winsize{Rows: 43, Cols: 117}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	_, _ = master.Write([]byte{3})
	time.Sleep(150 * time.Millisecond)
	_, _ = master.Write([]byte{3})
	select {
	case got := <-finished:
		settled = true
		if got.code != 0 || got.err != nil {
			t.Fatalf("raw target cancellation result = (%d, %v), terminal=%q", got.code, got.err, capture.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("raw target did not terminate after terminal cancellation")
	}
	// The harness retains its slave descriptor while ExecuteCodex is running.
	// Close that descriptor before the master so Darwin reliably delivers EOF
	// to the capture goroutine, including when the x86_64 target used Rosetta.
	_ = terminal.Close()
	_ = master.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("raw target terminal capture did not drain")
	}
	assertNoSessionDirectories(t, registry.sessionsDirectory)
	if provider.replaceCalls != 0 || !strings.Contains(string(provider.records[name].Auth), "access-secret") {
		t.Fatal("raw target lifecycle replaced the named identity")
	}
	binding, _, err := registry.resources.AcquireStatus(context.Background(), string(name))
	if err != nil {
		t.Fatalf("raw target lifecycle left identity unavailable: %v", err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
}

type directNativeCapture struct {
	mu     sync.Mutex
	buffer strings.Builder
}

func (capture *directNativeCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Write(contents)
}

func (capture *directNativeCapture) Len() int {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Len()
}

func (capture *directNativeCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String()
}

func runInstalledTargetVersion(binary string) (string, error) {
	output, err := exec.Command(binary, "--version").Output()
	return strings.TrimSpace(string(output)), err
}

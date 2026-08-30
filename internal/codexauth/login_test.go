package codexauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestContainedLoginPinsVersionUsesSyntheticHomeAndCleansSession(t *testing.T) {
	root := t.TempDir()
	sessionsDirectory := filepath.Join(root, "acs", "sessions")
	globalHome := filepath.Join(root, "global")
	globalAuth := filepath.Join(globalHome, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("global-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	sandbox := &fakeLoginSandbox{version: SupportedCodexVersion, auth: auth}
	runner := newCodexLoginRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: sessionsDirectory, WorkingDirectory: root,
	}, sandbox)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	got, err := runner.Login(context.Background(), true, launch.Terminal{
		Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(auth) {
		t.Fatal("login changed auth payload")
	}
	if gotArgs := sandbox.arguments; !reflect.DeepEqual(gotArgs, [][]string{{"--version"}, {"login", "--device-auth"}}) {
		t.Fatalf("arguments = %#v", gotArgs)
	}
	if sandbox.config != "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n" {
		t.Fatalf("synthetic config = %q", sandbox.config)
	}
	if !reflect.DeepEqual(sandbox.check.RuntimeProbePaths, []string{codexSystemRequirementsPath}) {
		t.Fatalf("sandbox check runtime probes = %q", sandbox.check.RuntimeProbePaths)
	}
	for _, request := range sandbox.requests {
		if !reflect.DeepEqual(request.RuntimeProbePaths, []string{codexSystemRequirementsPath}) {
			t.Fatalf("sandbox process runtime probes = %q", request.RuntimeProbePaths)
		}
	}
	global, err := os.ReadFile(globalAuth)
	if err != nil || string(global) != "global-sentinel" {
		t.Fatalf("global auth changed: %q, %v", global, err)
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("Session cleanup = (%d entries, %v)", len(entries), err)
	}
}

func TestContainedLoginUsesDefaultBrowserFlowWithoutDeviceFlag(t *testing.T) {
	root := t.TempDir()
	sandbox := &fakeLoginSandbox{
		version: SupportedCodexVersion,
		auth:    testChatGPTAuthJSON(t, "user", "workspace"),
	}
	runner := newCodexLoginRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: root,
	}, sandbox)
	if _, err := runner.Login(context.Background(), false, launch.Terminal{}); err != nil {
		t.Fatal(err)
	}
	if got := sandbox.arguments; !reflect.DeepEqual(got, [][]string{{"--version"}, {"login"}}) {
		t.Fatalf("arguments = %#v", got)
	}
}

func TestContainedLoginRejectsWrongVersionBeforeLogin(t *testing.T) {
	root := t.TempDir()
	sandbox := &fakeLoginSandbox{version: "0.999.0", auth: testChatGPTAuthJSON(t, "user", "workspace")}
	runner := newCodexLoginRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: root,
	}, sandbox)
	if _, err := runner.Login(context.Background(), false, launch.Terminal{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error = %v", err)
	}
	if len(sandbox.arguments) != 1 {
		t.Fatalf("wrong version still launched login: %#v", sandbox.arguments)
	}
}

func TestContainedLoginBoundsVersionOutput(t *testing.T) {
	root := t.TempDir()
	sandbox := &fakeLoginSandbox{version: strings.Repeat("x", maximumVersionOutputSize*2)}
	runner := newCodexLoginRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: root,
	}, sandbox)
	if _, err := runner.Login(context.Background(), false, launch.Terminal{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadPrivateAuthFileRejectsSymlinksAndBroadPermissions(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"auth_mode":"chatgpt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "auth.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateAuthFile(link); !errors.Is(err, ErrUnsupportedAuth) {
		t.Fatalf("symlink error = %v", err)
	}

	broad := filepath.Join(root, "broad.json")
	if err := os.WriteFile(broad, []byte(`{"auth_mode":"chatgpt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateAuthFile(broad); !errors.Is(err, ErrUnsupportedAuth) {
		t.Fatalf("broad-mode error = %v", err)
	}
}

func TestContainedLoginSanitizesTargetFailure(t *testing.T) {
	root := t.TempDir()
	sandbox := &fakeLoginSandbox{
		version: SupportedCodexVersion,
		waitErr: errors.New("secret target diagnostic"),
	}
	runner := newCodexLoginRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: root,
	}, sandbox)
	_, err := runner.Login(context.Background(), false, launch.Terminal{})
	if !errors.Is(err, ErrLoginFailed) || strings.Contains(err.Error(), "secret target diagnostic") {
		t.Fatalf("error = %v", err)
	}
}

type fakeLoginSandbox struct {
	version   string
	auth      []byte
	waitErr   error
	arguments [][]string
	config    string
	check     launch.SandboxCheck
	requests  []launch.ProcessRequest
}

func (*fakeLoginSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{Supported: true, Ready: true}, nil
}

func (sandbox *fakeLoginSandbox) Check(_ context.Context, check launch.SandboxCheck) error {
	sandbox.check = check
	return nil
}

func (sandbox *fakeLoginSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.arguments = append(sandbox.arguments, append([]string(nil), request.Arguments...))
	sandbox.requests = append(sandbox.requests, request)
	return &fakeLoginProcess{start: func() error {
		switch {
		case reflect.DeepEqual(request.Arguments, []string{"--version"}):
			_, err := io.WriteString(request.Terminal.Output, "codex-cli "+sandbox.version+"\n")
			return err
		case len(request.Arguments) > 0 && request.Arguments[0] == "login":
			configuration, err := os.ReadFile(filepath.Join(request.SessionHome, ".codex", "config.toml"))
			if err != nil {
				return err
			}
			sandbox.config = string(configuration)
			if sandbox.waitErr == nil {
				return os.WriteFile(filepath.Join(request.SessionHome, ".codex", "auth.json"), sandbox.auth, 0o600)
			}
		}
		return nil
	}, waitErr: sandbox.waitErr}, nil
}

type fakeLoginProcess struct {
	start   func() error
	waitErr error
}

func (process *fakeLoginProcess) Start() error {
	if process.start == nil {
		return nil
	}
	return process.start()
}

func (process *fakeLoginProcess) Wait() error            { return process.waitErr }
func (process *fakeLoginProcess) Signal(os.Signal) error { return nil }

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
	"github.com/alcimerio/ai-config-selector/internal/session"
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
	result, created := runLoginRunnerForTest(t, runner, true, launch.Terminal{
		Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &stderr,
	})
	if result.err != nil || !result.cleanupProven {
		t.Fatalf("login result = %#v", result)
	}
	defer clearBytes(result.auth)
	if string(result.auth) != string(auth) {
		t.Fatal("login changed auth payload")
	}
	wantArguments := [][]string{
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "--version"},
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "login", "--device-auth"},
	}
	if gotArgs := sandbox.arguments; !reflect.DeepEqual(gotArgs, wantArguments) {
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
	if err := created.Remove(); err != nil {
		t.Fatal(err)
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
	result, created := runLoginRunnerForTest(t, runner, false, launch.Terminal{})
	if result.err != nil || !result.cleanupProven {
		t.Fatalf("login result = %#v", result)
	}
	defer clearBytes(result.auth)
	defer created.Remove()
	wantArguments := [][]string{
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "--version"},
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "login"},
	}
	if got := sandbox.arguments; !reflect.DeepEqual(got, wantArguments) {
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
	result, created := runLoginRunnerForTest(t, runner, false, launch.Terminal{})
	defer created.Remove()
	if !errors.Is(result.err, ErrUnsupportedVersion) || !result.cleanupProven {
		t.Fatalf("result = %#v", result)
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
	result, created := runLoginRunnerForTest(t, runner, false, launch.Terminal{})
	defer created.Remove()
	if !errors.Is(result.err, ErrUnsupportedVersion) || !result.cleanupProven {
		t.Fatalf("result = %#v", result)
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
	result, created := runLoginRunnerForTest(t, runner, false, launch.Terminal{})
	defer created.Remove()
	if !errors.Is(result.err, ErrLoginFailed) || strings.Contains(result.err.Error(), "secret target diagnostic") {
		t.Fatalf("error = %v", result.err)
	}
}

func runLoginRunnerForTest(
	t *testing.T,
	runner *codexLoginRunner,
	deviceAuth bool,
	terminal launch.Terminal,
) (loginRunResult, *session.Session) {
	t.Helper()
	if err := runner.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	created, err := session.Create(
		runner.config.SessionsDirectory,
		runner.config.WorkingDirectory,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runner.Run(context.Background(), created, deviceAuth, terminal), created
}

func TestContainedStatusPinsAuthPolicyAtRuntimePrecedence(t *testing.T) {
	root := t.TempDir()
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, err := validateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	created, err := session.Create(filepath.Join(root, "sessions"), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	if err := projectCredential(created.HomeDirectory(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}

	sandbox := &fakeLoginSandbox{version: SupportedCodexVersion, auth: auth}
	runner := newCodexStatusRunner(codexLoginConfig{
		BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: root,
	}, sandbox)
	result := runner.Run(context.Background(), created, "workspace")
	if result.err != nil || !result.cleanupProven {
		t.Fatalf("status result = %#v", result)
	}
	wantArguments := [][]string{
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "-c", `forced_chatgpt_workspace_id="workspace"`, "--version"},
		{"-c", `cli_auth_credentials_store="file"`, "-c", `forced_login_method="chatgpt"`, "-c", `forced_chatgpt_workspace_id="workspace"`, "login", "status"},
	}
	if !reflect.DeepEqual(sandbox.arguments, wantArguments) {
		t.Fatalf("arguments = %#v", sandbox.arguments)
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
		commandArguments := request.Arguments
		for len(commandArguments) >= 2 && commandArguments[0] == "-c" {
			commandArguments = commandArguments[2:]
		}
		switch {
		case reflect.DeepEqual(commandArguments, []string{"--version"}):
			_, err := io.WriteString(request.Terminal.Output, "codex-cli "+sandbox.version+"\n")
			return err
		case len(commandArguments) > 0 && commandArguments[0] == "login":
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

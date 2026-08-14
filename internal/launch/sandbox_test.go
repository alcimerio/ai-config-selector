package launch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestValidatePlatformCoversSupportedMatrix(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		accepted bool
	}{
		{name: "macOS 26 arm64", platform: Platform{OS: "darwin", Architecture: "arm64", Release: "26.0"}, accepted: true},
		{name: "macOS 26 amd64", platform: Platform{OS: "darwin", Architecture: "amd64", Release: "26.9.1"}, accepted: true},
		{name: "Ubuntu 24.04 amd64", platform: Platform{OS: "linux", Architecture: "amd64", Distribution: "ubuntu", Release: "24.04"}, accepted: true},
		{name: "Ubuntu 24.04 arm64", platform: Platform{OS: "linux", Architecture: "arm64", Distribution: "ubuntu", Release: "24.04.3"}, accepted: true},
		{name: "old macOS", platform: Platform{OS: "darwin", Architecture: "arm64", Release: "15.6"}},
		{name: "future macOS", platform: Platform{OS: "darwin", Architecture: "amd64", Release: "27.0"}},
		{name: "old Ubuntu", platform: Platform{OS: "linux", Architecture: "amd64", Distribution: "ubuntu", Release: "22.04"}},
		{name: "future Ubuntu", platform: Platform{OS: "linux", Architecture: "arm64", Distribution: "ubuntu", Release: "26.04"}},
		{name: "other Linux", platform: Platform{OS: "linux", Architecture: "amd64", Distribution: "debian", Release: "24.04"}},
		{name: "unsupported Darwin architecture", platform: Platform{OS: "darwin", Architecture: "386", Release: "26.0"}},
		{name: "unsupported Linux architecture", platform: Platform{OS: "linux", Architecture: "riscv64", Distribution: "ubuntu", Release: "24.04"}},
		{name: "Windows", platform: Platform{OS: "windows", Architecture: "amd64", Release: "11"}},
		{name: "unknown OS", platform: Platform{Architecture: "amd64", Release: "24.04"}},
		{name: "unknown architecture", platform: Platform{OS: "darwin", Release: "26.0"}},
		{name: "unknown release", platform: Platform{OS: "darwin", Architecture: "arm64"}},
		{name: "unknown Linux distribution", platform: Platform{OS: "linux", Architecture: "amd64", Release: "24.04"}},
		{name: "malformed macOS release", platform: Platform{OS: "darwin", Architecture: "arm64", Release: "26.private"}},
		{name: "malformed Ubuntu release", platform: Platform{OS: "linux", Architecture: "amd64", Distribution: "ubuntu", Release: "24.04."}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePlatform(test.platform)
			if test.accepted && err != nil {
				t.Fatalf("supported platform rejected: %v", err)
			}
			if !test.accepted {
				if err == nil {
					t.Fatal("unsupported platform accepted")
				}
				assertSandboxCategory(t, err, SandboxUnsupportedPlatform)
			}
		})
	}
}

func TestSandboxErrorsExposeOnlyStableCategory(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "PRIVATE_WORKSPACE")
	err := sandboxError(SandboxUnsafePath, errors.New("backend rejected "+secret+" policy=(allow file-read*)"))
	assertSandboxCategory(t, err, SandboxUnsafePath)
	if got, want := err.Error(), "unsafe_path: process sandbox preparation failed: unsafe runtime path"; got != want {
		t.Fatalf("sandbox error = %q, want %q", got, want)
	}
	for _, private := range []string{secret, "PRIVATE_WORKSPACE", "backend rejected", "policy"} {
		if strings.Contains(err.Error(), private) {
			t.Fatalf("sandbox error leaked %q: %v", private, err)
		}
	}
	unknown := (&SandboxError{Category: SandboxErrorCategory("PRIVATE_CATEGORY")}).Error()
	if got, want := unknown, "setup_failed: process sandbox preparation failed"; got != want {
		t.Fatalf("unknown sandbox error = %q, want %q", got, want)
	}
}

func TestBubblewrapUnavailableProvidesFixedPackageRemediationWithoutBackendOutput(t *testing.T) {
	err := bubblewrapUnavailable()
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
	if got, want := err.Error(), "backend_unavailable: process sandbox unavailable: required system backend is unavailable; install or repair the signed Ubuntu package with 'sudo apt-get install --reinstall bubblewrap'"; got != want {
		t.Fatalf("Bubblewrap unavailable error = %q, want %q", got, want)
	}
	for _, private := range []string{"PRIVATE_BACKEND_OUTPUT", "/home/alice", "policy=(allow"} {
		if strings.Contains(err.Error(), private) {
			t.Fatalf("Bubblewrap remediation leaked %q: %v", private, err)
		}
	}
}

func TestValidateProcessPathsResolvesInputsAndRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "home", "user", "project")
	sessions := filepath.Join(root, "home", "user", ".acs", "sessions")
	session := filepath.Join(sessions, "session-one")
	sessionHome := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	executable := filepath.Join(root, "bin", "devin")
	runtimeInput := filepath.Join(root, "runtime", "ca.pem")
	for _, directory := range []string{workspace, sessionHome, temporary, filepath.Dir(executable), filepath.Dir(runtimeInput)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeInput, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	validated, err := validateProcessRequest(ProcessRequest{
		Workspace:          workspace,
		SessionsDirectory:  sessions,
		SessionDirectory:   session,
		SessionHome:        sessionHome,
		TemporaryDirectory: temporary,
		Executable:         executable,
		RuntimeInputs:      []string{runtimeInput},
	})
	if err != nil {
		t.Fatalf("valid process paths rejected: %v", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if !pathWithin(resolvedRoot, validated.workspace) || filepath.Base(validated.sessionDirectory) != "session-one" || filepath.Base(validated.executable) != "devin" {
		t.Fatalf("validated paths = %#v", validated)
	}

	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(session, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	_, err = validateProcessRequest(ProcessRequest{
		Workspace: workspace, SessionsDirectory: sessions, SessionDirectory: session,
		SessionHome: sessionHome, TemporaryDirectory: escape, Executable: executable,
	})
	if err == nil {
		t.Fatal("symlink escape accepted as the Session temporary directory")
	}
	assertSandboxCategory(t, err, SandboxUnsafePath)
}

func TestValidateSandboxCheckRejectsMissingAndUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		request SandboxCheck
	}{
		{name: "relative workspace", request: SandboxCheck{Workspace: "relative", SessionsDirectory: filepath.Join(root, "sessions"), Executable: os.Args[0]}},
		{name: "root workspace", request: SandboxCheck{Workspace: string(filepath.Separator), SessionsDirectory: filepath.Join(root, "sessions"), Executable: os.Args[0]}},
		{name: "workspace contains sessions", request: SandboxCheck{Workspace: root, SessionsDirectory: filepath.Join(root, "sessions"), Executable: os.Args[0]}},
		{name: "missing workspace", request: SandboxCheck{Workspace: filepath.Join(root, "missing"), SessionsDirectory: filepath.Join(root, "sessions"), Executable: os.Args[0]}},
		{name: "missing executable", request: SandboxCheck{Workspace: workspace, SessionsDirectory: filepath.Join(root, "sessions"), Executable: filepath.Join(root, "missing-devin")}},
		{name: "relative sessions", request: SandboxCheck{Workspace: workspace, SessionsDirectory: "sessions", Executable: os.Args[0]}},
		{name: "missing runtime input", request: SandboxCheck{Workspace: workspace, SessionsDirectory: filepath.Join(root, "sessions"), Executable: os.Args[0], RuntimeInputs: []string{filepath.Join(root, "missing-runtime")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateSandboxCheck(test.request); err == nil {
				t.Fatal("unsafe input accepted")
			} else {
				assertSandboxCategory(t, err, SandboxUnsafePath)
			}
		})
	}
}

func TestValidateSandboxCheckRejectsBroadRuntimeMounts(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "home", "user", "project")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(root, "home", "user", ".acs", "sessions")
	for _, input := range []string{string(filepath.Separator), filepath.Join(root, "home"), filepath.Join(root, "home", "user"), workspace} {
		_, err := validateSandboxCheck(SandboxCheck{
			Workspace: workspace, SessionsDirectory: sessions, Executable: os.Args[0], RuntimeInputs: []string{input},
		})
		if err == nil {
			t.Fatalf("accepted broad runtime input %q", input)
		}
		assertSandboxCategory(t, err, SandboxUnsafePath)
	}
}

func TestBuildProcessEnvironmentUsesOnlySessionAndSafeTerminalLocaleValues(t *testing.T) {
	host := []string{
		"HOME=/private/home", "PATH=/private/bin", "AWS_SECRET_ACCESS_KEY=secret",
		"SSH_AUTH_SOCK=/private/agent.sock", "HTTP_PROXY=http://private.proxy",
		"DYLD_INSERT_LIBRARIES=/private/inject.dylib", "TERM=xterm-256color",
		"COLORTERM=truecolor", "LANG=en_US.UTF-8", "LC_ALL=C.UTF-8", "LC_CTYPE=en_US.UTF-8",
		"NO_COLOR=1", "TERM_PROGRAM=private-terminal",
	}
	got, err := buildProcessEnvironment("/session/home", "/session/tmp", host)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"HOME=/session/home",
		"XDG_CONFIG_HOME=/session/home/.config",
		"XDG_DATA_HOME=/session/home/.local/share",
		"XDG_CACHE_HOME=/session/home/.cache",
		"XDG_STATE_HOME=/session/home/.local/state",
		"TMPDIR=/session/tmp",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=en_US.UTF-8",
		"LC_ALL=C.UTF-8",
		"LC_CTYPE=en_US.UTF-8",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestBuildProcessEnvironmentRejectsUnexpectedAllowedValueWithoutLeakingIt(t *testing.T) {
	err := func() error {
		_, err := buildProcessEnvironment("/session/home", "/session/tmp", []string{"TERM=xterm\nPRIVATE_VALUE"})
		return err
	}()
	if err == nil {
		t.Fatal("unsafe terminal value accepted")
	}
	assertSandboxCategory(t, err, SandboxInvalidEnvironment)
	if strings.Contains(err.Error(), "PRIVATE_VALUE") {
		t.Fatalf("environment error leaked value: %v", err)
	}
}

func TestValidateTerminalRejectsExtraFileDescriptor(t *testing.T) {
	extra, err := os.CreateTemp(t.TempDir(), "extra-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()

	err = validateTerminal(Terminal{Input: extra, Output: os.Stdout, ErrorOutput: os.Stderr})
	if err == nil {
		t.Fatal("extra file descriptor accepted as the invoking terminal")
	}
	assertSandboxCategory(t, err, SandboxInvalidDescriptor)
	if err := validateTerminal(Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}); err != nil {
		t.Fatalf("standard terminal descriptors rejected: %v", err)
	}
}

func TestProcessSandboxRejectsMissingBackendBeforePathPreparation(t *testing.T) {
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
		nil,
	)
	err := sandbox.Check(context.Background(), SandboxCheck{})
	if err == nil {
		t.Fatal("sandbox accepted a supported platform without a backend")
	}
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
}

func TestProcessSandboxSelectsBackendAndPassesOnlyValidatedInputs(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "home", "user", "workspace")
	sessions := filepath.Join(root, "home", "user", ".acs", "sessions")
	session := filepath.Join(sessions, "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	executable := filepath.Join(root, "bin", "devin")
	for _, directory := range []string{workspace, home, temporary, filepath.Dir(executable)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	backend := &capturingBackend{}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
		map[string]sandboxBackend{"darwin": backend},
	)
	sandbox.environ = func() []string { return []string{"TERM=xterm-256color", "AWS_SECRET_ACCESS_KEY=PRIVATE_VALUE"} }
	process, err := sandbox.Prepare(context.Background(), ProcessRequest{
		Workspace: workspace, SessionsDirectory: sessions, SessionDirectory: session,
		SessionHome: home, TemporaryDirectory: temporary, Executable: executable,
		Arguments: []string{"auth", "status"},
	})
	if err != nil {
		t.Fatalf("prepare sandbox: %v", err)
	}
	if process == nil || backend.request.workspace == "" {
		t.Fatal("selected backend did not receive a prepared process")
	}
	if filepath.Base(backend.request.workspace) != "workspace" || filepath.Base(backend.request.sessionDirectory) != "session-one" {
		t.Fatalf("backend paths = %#v", backend.request)
	}
	if got := strings.Join(backend.request.environment, "\n"); strings.Contains(got, "PRIVATE_VALUE") || !strings.Contains(got, "TERM=xterm-256color") {
		t.Fatalf("backend environment was not filtered: %q", got)
	}
}

func TestProcessSandboxSanitizesBackendFailures(t *testing.T) {
	secret := "PRIVATE_BACKEND_OUTPUT policy=(allow default)"
	backend := &capturingBackend{checkErr: errors.New(secret)}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			return Platform{OS: "linux", Architecture: "amd64", Distribution: "ubuntu", Release: "24.04"}, nil
		},
		map[string]sandboxBackend{"linux": backend},
	)
	err := sandbox.Check(context.Background(), SandboxCheck{})
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "policy") {
		t.Fatalf("backend failure leaked private output: %v", err)
	}
}

func TestProcessSandboxRebuildsClassifiedBackendFailures(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "PRIVATE_BACKEND_PATH")
	tests := []struct {
		name     string
		category SandboxErrorCategory
		message  string
		wrapped  bool
		invoke   func(*nativeProcessSandbox) error
	}{
		{
			name:     "direct validation failure",
			category: SandboxBackendUnavailable,
			message:  "backend_unavailable: process sandbox unavailable: required system backend is unavailable",
			invoke: func(sandbox *nativeProcessSandbox) error {
				return sandbox.Check(context.Background(), SandboxCheck{})
			},
		},
		{
			name:     "wrapped validation failure",
			category: SandboxUnsupportedPlatform,
			message:  "unsupported_platform: process sandbox unavailable: unsupported platform",
			wrapped:  true,
			invoke: func(sandbox *nativeProcessSandbox) error {
				return sandbox.Check(context.Background(), SandboxCheck{})
			},
		},
		{
			name:     "direct preparation failure",
			category: SandboxSetupFailed,
			message:  "setup_failed: process sandbox preparation failed",
			invoke: func(sandbox *nativeProcessSandbox) error {
				_, err := sandbox.Prepare(context.Background(), validProcessRequest(t))
				return err
			},
		},
		{
			name:     "wrapped preparation failure",
			category: SandboxInvalidEnvironment,
			message:  "invalid_environment: process sandbox preparation failed: invalid environment",
			wrapped:  true,
			invoke: func(sandbox *nativeProcessSandbox) error {
				_, err := sandbox.Prepare(context.Background(), validProcessRequest(t))
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := &SandboxError{Category: test.category}
			backendErr := error(classified)
			if test.wrapped {
				backendErr = fmt.Errorf("backend output %s ENV=PRIVATE_VALUE policy=(allow default): %w", secret, classified)
			}
			backend := &capturingBackend{}
			if strings.Contains(test.name, "validation") {
				backend.checkErr = backendErr
			} else {
				backend.prepareErr = backendErr
			}
			sandbox := newNativeProcessSandbox(
				func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
				map[string]sandboxBackend{"darwin": backend},
			)

			err := test.invoke(sandbox)
			stable, ok := err.(*SandboxError)
			if !ok {
				t.Fatalf("error type = %T, want direct *SandboxError: %v", err, err)
			}
			if stable == classified {
				t.Fatal("sandbox returned the backend-supplied SandboxError")
			}
			if stable.Category != test.category {
				t.Fatalf("category = %q, want %q", stable.Category, test.category)
			}
			if got := stable.Error(); got != test.message {
				t.Fatalf("message = %q, want %q", got, test.message)
			}
			for _, private := range []string{secret, "PRIVATE_BACKEND_PATH", "PRIVATE_VALUE", "backend output", "policy"} {
				if strings.Contains(err.Error(), private) {
					t.Fatalf("classified backend failure leaked %q: %v", private, err)
				}
			}
		})
	}
}

func TestPreparedProcessSanitizesStartAndNonExitWaitFailures(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "PRIVATE_EXECUTABLE")
	request := validProcessRequest(t)
	tests := []struct {
		name    string
		process Process
		invoke  func(Process) error
		want    SandboxErrorCategory
	}{
		{
			name:    "start",
			process: &stubLifecycleProcess{startErr: errors.New("start " + secret + " ENV=PRIVATE_VALUE")},
			invoke:  func(process Process) error { return process.Start() },
			want:    SandboxProcessStartFailed,
		},
		{
			name:    "wait",
			process: &stubLifecycleProcess{waitErr: errors.New("wait " + secret + " policy=(allow file-read*)")},
			invoke:  func(process Process) error { return process.Wait() },
			want:    SandboxProcessWaitFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &capturingBackend{process: test.process}
			sandbox := newNativeProcessSandbox(
				func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
				map[string]sandboxBackend{"darwin": backend},
			)
			process, err := sandbox.Prepare(context.Background(), request)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			err = test.invoke(process)
			assertSandboxCategory(t, err, test.want)
			for _, private := range []string{secret, "PRIVATE_EXECUTABLE", "PRIVATE_VALUE", "policy"} {
				if strings.Contains(err.Error(), private) {
					t.Fatalf("process lifecycle error leaked %q: %v", private, err)
				}
			}
		})
	}
}

func TestPreparedProcessPreservesChildExitStatus(t *testing.T) {
	exitError := &exec.ExitError{}
	backend := &capturingBackend{process: &stubLifecycleProcess{waitErr: exitError}}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) { return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil },
		map[string]sandboxBackend{"darwin": backend},
	)
	process, err := sandbox.Prepare(context.Background(), validProcessRequest(t))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := process.Wait(); err != exitError {
		t.Fatalf("Wait error = %T %v, want original child exit error", err, err)
	}
}

func TestCurrentPlatformMatchesRuntimeFamily(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatalf("identify current platform: %v", err)
	}
	if platform.OS != runtime.GOOS || platform.Architecture != runtime.GOARCH || platform.Release == "" {
		t.Fatalf("current platform = %#v", platform)
	}
}

func assertSandboxCategory(t *testing.T, err error, want SandboxErrorCategory) {
	t.Helper()
	var sandboxFailure *SandboxError
	if !errors.As(err, &sandboxFailure) {
		t.Fatalf("error type = %T, want *SandboxError: %v", err, err)
	}
	if sandboxFailure.Category != want {
		t.Fatalf("category = %q, want %q", sandboxFailure.Category, want)
	}
}

type capturingBackend struct {
	checkErr   error
	prepareErr error
	request    validatedProcessRequest
	process    Process
}

func (backend *capturingBackend) check(context.Context) error { return backend.checkErr }
func (backend *capturingBackend) prepare(_ context.Context, request validatedProcessRequest) (Process, error) {
	backend.request = request
	if backend.prepareErr != nil {
		return nil, backend.prepareErr
	}
	if backend.process != nil {
		return backend.process, nil
	}
	return stubProcess{}, nil
}

type stubProcess struct{}

func (stubProcess) Start() error           { return nil }
func (stubProcess) Wait() error            { return nil }
func (stubProcess) Signal(os.Signal) error { return nil }

type stubLifecycleProcess struct {
	startErr error
	waitErr  error
}

func (process *stubLifecycleProcess) Start() error           { return process.startErr }
func (process *stubLifecycleProcess) Wait() error            { return process.waitErr }
func (process *stubLifecycleProcess) Signal(os.Signal) error { return nil }

func validProcessRequest(t *testing.T) ProcessRequest {
	t.Helper()
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	session := filepath.Join(sessions, "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	executable := filepath.Join(root, "devin")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return ProcessRequest{
		Workspace: workspace, SessionsDirectory: sessions, SessionDirectory: session,
		SessionHome: home, TemporaryDirectory: temporary, Executable: executable,
	}
}

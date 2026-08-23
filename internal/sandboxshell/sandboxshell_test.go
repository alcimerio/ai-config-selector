package sandboxshell

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type shellSelection struct{ marker string }

func (selection shellSelection) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Selected Skills:"})
	return nil
}

func (selection shellSelection) Materialize(home string) error {
	bundle := filepath.Join(home, ".agents", "skills", "review")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(selection.marker), 0o600); err != nil {
		return err
	}
	for _, startupFile := range []string{".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
		if err := os.WriteFile(filepath.Join(home, startupFile), []byte("print -r -- startup-file-loaded\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (shellSelection) Verify(context.Context, launch.VerificationContext) error { return nil }

type recordingSandbox struct {
	check      launch.SandboxCheck
	request    launch.ProcessRequest
	process    *recordingProcess
	inspect    func(launch.ProcessRequest) error
	checkErr   error
	prepareErr error
}

func (sandbox *recordingSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{RequiredMode: "native", Backend: "Seatbelt", Platform: "macOS 26 arm64", Supported: true, Ready: true}, nil
}

func (sandbox *recordingSandbox) Check(_ context.Context, check launch.SandboxCheck) error {
	sandbox.check = check
	return sandbox.checkErr
}

func TestLaunchSandboxFailureUsesTargetNeutralFailClosedDiagnostic(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	sandbox := &recordingSandbox{
		process:  &recordingProcess{},
		checkErr: &launch.SandboxError{Category: launch.SandboxBackendUnavailable},
	}
	_, err := newLauncher(sandbox).Launch(
		context.Background(),
		sessionsDirectory,
		t.TempDir(),
		resolvedShellProfile(t),
		launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	)
	if err == nil {
		t.Fatal("sandbox launch unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "Devin") {
		t.Fatalf("target-neutral sandbox failure mentions Devin: %v", err)
	}
	if !strings.Contains(err.Error(), "ACS will not start the requested process without the required sandbox") {
		t.Fatalf("sandbox failure omits fail-closed diagnostic: %v", err)
	}
	var sandboxFailure *launch.SandboxError
	if !errors.As(err, &sandboxFailure) || sandboxFailure.Category != launch.SandboxBackendUnavailable {
		t.Fatalf("sandbox failure = %v", err)
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("backend check failure leased a Session: %v", err)
	}
}

func (sandbox *recordingSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.request = request
	if sandbox.inspect != nil {
		if err := sandbox.inspect(request); err != nil {
			return nil, err
		}
	}
	if sandbox.prepareErr != nil {
		return nil, sandbox.prepareErr
	}
	return sandbox.process, nil
}

func TestLaunchPreparationFailureRemovesMaterializedSession(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	sandbox := &recordingSandbox{
		process:    &recordingProcess{},
		prepareErr: &launch.SandboxError{Category: launch.SandboxPolicyRejected},
	}
	var sessionRoot string
	sandbox.inspect = func(request launch.ProcessRequest) error {
		sessionRoot = request.SessionDirectory
		return nil
	}

	_, err := newLauncher(sandbox).Launch(
		context.Background(), sessionsDirectory, t.TempDir(), resolvedShellProfile(t),
		launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	)
	var sandboxFailure *launch.SandboxError
	if !errors.As(err, &sandboxFailure) || sandboxFailure.Category != launch.SandboxPolicyRejected {
		t.Fatalf("prepare failure = %v", err)
	}
	if _, err := os.Stat(sessionRoot); !os.IsNotExist(err) {
		t.Fatalf("prepare failure left Session behind: %v", err)
	}
}

type recordingProcess struct {
	started bool
	waited  bool
	waitErr error
}

func (process *recordingProcess) Start() error   { process.started = true; return nil }
func (process *recordingProcess) Wait() error    { process.waited = true; return process.waitErr }
func (*recordingProcess) Signal(os.Signal) error { return nil }

func TestLaunchRunsFixedCleanShellWithMaterializedProfileAndNoDevinCredential(t *testing.T) {
	resolved := resolvedShellProfile(t)
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	workingDirectory := t.TempDir()
	process := &recordingProcess{}
	sandbox := &recordingSandbox{process: process}
	var sessionRoot string
	sandbox.inspect = func(request launch.ProcessRequest) error {
		sessionRoot = request.SessionDirectory
		if _, err := os.Stat(filepath.Join(request.SessionHome, ".agents", "skills", "review", "SKILL.md")); err != nil {
			t.Fatalf("selected Skill unavailable inside Session: %v", err)
		}
		credential := filepath.Join(request.SessionHome, ".local", "share", "devin", "credentials.toml")
		if _, err := os.Stat(credential); !os.IsNotExist(err) {
			t.Fatalf("sandbox shell Session contains a Devin credential: %v", err)
		}
		return nil
	}
	launcher := newLauncher(sandbox)
	terminal := launch.Terminal{Input: io.Reader(nil), Output: io.Discard, ErrorOutput: io.Discard}

	exitCode, err := launcher.Launch(context.Background(), sessionsDirectory, workingDirectory, resolved, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if sandbox.check.Executable != "/bin/zsh" || len(sandbox.check.RuntimeInputs) != 0 {
		t.Fatalf("sandbox check = %#v, want fixed /bin/zsh without runtime inputs", sandbox.check)
	}
	if sandbox.request.Executable != "/bin/zsh" || !reflect.DeepEqual(sandbox.request.Arguments, []string{"-f"}) {
		t.Fatalf("prepared command = %q %q, want /bin/zsh [-f]", sandbox.request.Executable, sandbox.request.Arguments)
	}
	if sandbox.request.Terminal != terminal {
		t.Fatal("prepared shell did not receive the invoking terminal")
	}
	if !process.started || !process.waited {
		t.Fatalf("process lifecycle = started %t, waited %t", process.started, process.waited)
	}
	if _, err := os.Stat(sessionRoot); !os.IsNotExist(err) {
		t.Fatalf("completed shell left its Session behind: %v", err)
	}
}

func TestLaunchPreservesOrdinaryShellExitStatusAndCleansSession(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 23")
	waitErr := command.Run()
	if waitErr == nil {
		t.Fatal("exit fixture unexpectedly succeeded")
	}
	process := &recordingProcess{waitErr: waitErr}
	sandbox := &recordingSandbox{process: process}
	var sessionRoot string
	sandbox.inspect = func(request launch.ProcessRequest) error {
		sessionRoot = request.SessionDirectory
		return nil
	}

	exitCode, err := newLauncher(sandbox).Launch(
		context.Background(), filepath.Join(t.TempDir(), "sessions"), t.TempDir(), resolvedShellProfile(t),
		launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	)
	var targetExit *ExitError
	if !errors.As(err, &targetExit) || exitCode != 23 || targetExit.ExitCode() != 23 {
		t.Fatalf("shell exit = code %d, error %v", exitCode, err)
	}
	if _, err := os.Stat(sessionRoot); !os.IsNotExist(err) {
		t.Fatalf("ordinary shell exit left Session behind: %v", err)
	}
}

func resolvedShellProfile(t *testing.T) category.ResolvedProfile {
	t.Helper()
	binding, err := category.Bind(category.Definition[string, string, shellSelection]{
		ID:            "skills",
		SchemaVersion: 1,
		Empty:         func() string { return "" },
		Resolve:       func(context.Context, string) (string, error) { return "selected", nil },
		Contribute:    func(resolved string) (shellSelection, error) { return shellSelection{marker: resolved}, nil },
		Count:         func(string) int { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, "review"); err != nil {
		t.Fatal(err)
	}
	profile, err := registry.NewProfile("review", draft)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

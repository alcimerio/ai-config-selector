package devin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestLaunchRunsPreflightBeforeInteractiveDevinAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	recorder := &recordingSandbox{delegate: directSandbox{}}
	fixture.sandbox = recorder
	workingDirectory := t.TempDir()

	eventsPath := filepath.Join(t.TempDir(), "events")
	t.Setenv("FAKE_DEVIN_EVENTS", eventsPath)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf 'preflight-skills\n' >> "$FAKE_DEVIN_EVENTS"
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'preflight-auth\n' >> "$FAKE_DEVIN_EVENTS"
  printf 'Logged in (via fixture).\n'
  exit 0
fi
printf 'launch-args=%s:%s\n' "$#" "$*" >> "$FAKE_DEVIN_EVENTS"
IFS= read -r line
printf 'stdout:%s\n' "$line"
printf 'stderr:%s\n' "$line" >&2
exit 23
`
	binaryPath := writeFakeDevin(t, script)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, workingDirectory, strings.NewReader("terminal input\n"), &stdout, &stderr)

	exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	if exitCode != 23 {
		t.Fatalf("exit code = %d, want child exit code 23; stderr: %s", exitCode, stderr.String())
	}
	if stdout.String() != "stdout:terminal input\n" {
		t.Fatalf("Devin stdout = %q, want attached terminal output", stdout.String())
	}
	if stderr.String() != "stderr:terminal input\n" {
		t.Fatalf("Devin stderr = %q, want attached terminal error output", stderr.String())
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(events), "preflight-skills\npreflight-auth\nlaunch-args=0:\n"; got != want {
		t.Fatalf("Devin events = %q, want %q", got, want)
	}
	if got, want := recorder.arguments, [][]string{{"skills", "list", "--json"}, {"auth", "status"}, nil}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox process arguments = %#v, want %#v", got, want)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("launch left Session data behind: %v", entries)
	}
}

func TestLaunchRejectsUnavailableSandboxBeforeCreatingSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	fixture.sandbox = failingSandbox{checkErr: &launch.SandboxError{Category: launch.SandboxBackendUnavailable}}
	marker := filepath.Join(t.TempDir(), "target-started")
	script := "#!/bin/sh\ntouch " + strconv.Quote(marker) + "\n"
	var stderr bytes.Buffer
	application := fixture.application(t, writeFakeDevin(t, script), t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded without a sandbox backend")
	}
	if !strings.Contains(stderr.String(), string(launch.SandboxBackendUnavailable)) && !strings.Contains(stderr.String(), "required system backend") {
		t.Fatalf("sandbox diagnostic lacks its stable category: %s", stderr.String())
	}
	if _, err := os.Stat(fixture.sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("early sandbox failure created a Session: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target started after early sandbox failure: %v", err)
	}
}

func TestLaunchRemovesUnusedSessionWhenSandboxSetupFails(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	fixture.sandbox = failingSandbox{prepareErr: &launch.SandboxError{Category: launch.SandboxSetupFailed}}
	marker := filepath.Join(t.TempDir(), "target-started")
	script := "#!/bin/sh\ntouch " + strconv.Quote(marker) + "\n"
	application := fixture.application(t, writeFakeDevin(t, script), t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded after sandbox setup failed")
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("sandbox setup failure left Session data behind: %v", entries)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target started after sandbox setup failure: %v", err)
	}
}

func TestLaunchRetainsSessionWhileStartupCleanupIsQuarantined(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	cleanupDone := make(chan struct{})
	quarantine := &startupQuarantineSandbox{delegate: directSandbox{}, cleanupDone: cleanupDone}
	fixture.sandbox = quarantine
	application := fixture.application(
		t,
		writeFakeDevin(t, successfulDevinScript("exit 0\n")),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	exitCode, err := application.adapter.Launch(
		context.Background(), application.sessionsDirectory, application.workingDirectory,
		application.resolved, application.terminal,
	)
	if exitCode != 1 || err == nil {
		t.Fatalf("launch result = (%d, %v), want bounded startup failure", exitCode, err)
	}
	if quarantine.sessionRoot == "" {
		t.Fatal("startup quarantine did not observe the Session")
	}
	if _, err := os.Stat(quarantine.sessionRoot); err != nil {
		t.Fatalf("Adapter removed Session before startup quarantine completed: %v", err)
	}

	concurrent, err := launch.CreateSession(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(quarantine.sessionRoot); err != nil {
		t.Fatalf("later Session cleanup removed startup quarantine's active Session: %v", err)
	}
	if err := concurrent.Remove(); err != nil {
		t.Fatal(err)
	}

	close(cleanupDone)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(quarantine.sessionRoot); os.IsNotExist(err) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Session remained after startup quarantine completed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLaunchRemovesAbandonedSessionFromAnEarlierRun(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	abandonedSession := filepath.Join(fixture.sessionsDirectory, "session-abandoned")
	if err := os.MkdirAll(filepath.Join(abandonedSession, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abandonedSession, "left-behind"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := successfulDevinScript("exit 0\n")
	application := fixture.application(
		t,
		writeFakeDevin(t, script),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode != 0 {
		t.Fatalf("launch exit code = %d, want 0", exitCode)
	}
	if _, err := os.Stat(abandonedSession); !os.IsNotExist(err) {
		t.Fatalf("later launch did not remove abandoned Session: %v", err)
	}
}

func TestLaterLaunchPreservesAConcurrentActiveSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	claimPath := filepath.Join(t.TempDir(), "first-claimed")
	readyPath := filepath.Join(t.TempDir(), "first-ready")
	releasePath := filepath.Join(t.TempDir(), "release-first")
	t.Setenv("FAKE_DEVIN_FIRST_CLAIM", claimPath)
	t.Setenv("FAKE_DEVIN_FIRST_READY", readyPath)
	t.Setenv("FAKE_DEVIN_RELEASE_FIRST", releasePath)
	script := successfulDevinScript(`if mkdir "$FAKE_DEVIN_FIRST_CLAIM" 2>/dev/null; then
  printf '%s\n' "$HOME" > "$FAKE_DEVIN_FIRST_READY"
  while [ ! -e "$FAKE_DEVIN_RELEASE_FIRST" ]; do sleep 0.05; done
fi
exit 0
`)
	binaryPath := writeFakeDevin(t, script)
	firstApplication := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	secondApplication := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	firstExitCodes := make(chan int, 1)
	go func() {
		firstExitCodes <- firstApplication.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	homeBytes, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatal(err)
	}
	firstSession := filepath.Dir(strings.TrimSpace(string(homeBytes)))

	secondExitCode := secondApplication.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	_, activeSessionErr := os.Stat(firstSession)
	if err := os.WriteFile(releasePath, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case firstExitCode := <-firstExitCodes:
		if firstExitCode != 0 {
			t.Errorf("first launch exit code = %d, want 0", firstExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first launch to exit")
	}
	if secondExitCode != 0 {
		t.Errorf("second launch exit code = %d, want 0", secondExitCode)
	}
	if activeSessionErr != nil {
		t.Fatalf("later launch removed a concurrent active Session: %v", activeSessionErr)
	}
}

func TestLaunchForwardsSignalsToDevinAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)

	readyPath := filepath.Join(t.TempDir(), "ready")
	signalPath := filepath.Join(t.TempDir(), "signal")
	t.Setenv("FAKE_DEVIN_READY", readyPath)
	t.Setenv("FAKE_DEVIN_SIGNAL", signalPath)
	script := successfulDevinScript(`trap 'printf "SIGTERM\n" > "$FAKE_DEVIN_SIGNAL"; exit 42' TERM
touch "$FAKE_DEVIN_READY"
while :; do sleep 1; done
`)
	binaryPath := writeFakeDevin(t, script)
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode != 42 {
			t.Fatalf("exit code = %d, want signaled Devin exit code 42", exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for signaled Devin to exit")
	}
	signal, err := os.ReadFile(signalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(signal) != "SIGTERM\n" {
		t.Fatalf("forwarded signal record = %q, want SIGTERM", signal)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("signaled launch left Session data behind: %v", entries)
	}
}

func TestLaunchForwardsTerminalResizeEventToDevin(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	readyPath := filepath.Join(t.TempDir(), "ready")
	resizePath := filepath.Join(t.TempDir(), "resize")
	t.Setenv("FAKE_DEVIN_READY", readyPath)
	t.Setenv("FAKE_DEVIN_RESIZE", resizePath)
	script := successfulDevinScript(`trap 'printf "SIGWINCH\n" > "$FAKE_DEVIN_RESIZE"' WINCH
touch "$FAKE_DEVIN_READY"
while [ ! -e "$FAKE_DEVIN_RESIZE" ]; do sleep 0.05; done
exit 0
`)
	application := fixture.application(
		t,
		writeFakeDevin(t, script),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 after resize", exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for resized Devin to exit")
	}
	resize, err := os.ReadFile(resizePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(resize) != "SIGWINCH\n" {
		t.Fatalf("resize record = %q, want SIGWINCH", resize)
	}
}

func TestRunAttachedDoesNotCancelAndReforwardOneSignalDuringStart(t *testing.T) {
	preflightContext, cancelPreflight := context.WithCancel(context.Background())
	defer cancelPreflight()
	supervisor := newSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	process := &startAttachRaceProcess{preflightContext: preflightContext}

	if err := runAttached(process, supervisor); err != nil {
		t.Fatal(err)
	}
	if got, want := process.receivedSignals(), []syscall.Signal{syscall.SIGTERM}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signal handoff = %v, want one forwarded SIGTERM", got)
	}
}

func TestLaunchSignalDuringPreflightCancelsVerificationAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	readyPath := filepath.Join(t.TempDir(), "preflight-ready")
	t.Setenv("FAKE_DEVIN_PREFLIGHT_READY", readyPath)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  touch "$FAKE_DEVIN_PREFLIGHT_READY"
  sleep 30
  exit 0
fi
exit 64
`
	binaryPath := writeFakeDevin(t, script)
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode == 0 {
			t.Fatal("launch succeeded after preflight was interrupted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for interrupted preflight to exit")
	}
	if !strings.Contains(stderr.String(), "verification was canceled or timed out") {
		t.Fatalf("interrupted-preflight error is unclear: %s", stderr.String())
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("interrupted preflight left Session data behind: %v", entries)
	}
}

func TestLaunchPreflightFailureReportsSanitizedCatalogAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)

	launchMarker := filepath.Join(t.TempDir(), "launched")
	t.Setenv("FAKE_DEVIN_LAUNCH_MARKER", launchMarker)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf '[{"name":"token=SUPER_SECRET_STDOUT","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/SUPER_SECRET_PATH"
  printf 'token=SUPER_SECRET\n' >&2
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'Logged in (via fixture).\n'
  exit 0
fi
touch "$FAKE_DEVIN_LAUNCH_MARKER"
exit 0
`
	binaryPath := writeFakeDevin(t, script)
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded after Adapter Preflight catalog mismatch")
	}
	for _, detail := range []string{"skill isolation", "global Skill Catalog did not match", "incompatible"} {
		if !strings.Contains(stderr.String(), detail) {
			t.Errorf("preflight diagnostic does not contain %q: %s", detail, stderr.String())
		}
	}
	for _, sensitive := range []string{"SUPER_SECRET", "devin-config:review"} {
		if strings.Contains(stderr.String(), sensitive) {
			t.Fatalf("preflight diagnostic leaked catalog data: %s", stderr.String())
		}
	}
	if _, err := os.Stat(launchMarker); !os.IsNotExist(err) {
		t.Fatalf("Devin started after failed preflight: %v", err)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed preflight left Session data behind: %v", entries)
	}
}

type launchTestFixture struct {
	existingHome      string
	sessionsDirectory string
	sandbox           launch.ProcessSandbox
}

func newLaunchTestFixture(t *testing.T) launchTestFixture {
	t.Helper()
	existingHome := t.TempDir()
	bundlePath := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	if err := os.MkdirAll(bundlePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return launchTestFixture{
		existingHome:      existingHome,
		sessionsDirectory: filepath.Join(t.TempDir(), "sessions"),
		sandbox:           directSandbox{},
	}
}

type adapterLaunchApplication struct {
	adapter           *Adapter
	resolved          category.ResolvedProfile
	sessionsDirectory string
	workingDirectory  string
	terminal          launch.Terminal
}

func (fixture launchTestFixture) application(
	t *testing.T,
	binaryPath string,
	workingDirectory string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) adapterLaunchApplication {
	t.Helper()
	adapter, err := newAdapter(Config{BinaryPath: binaryPath, ExistingHomeDir: fixture.existingHome}, fixture.sandbox)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := adapter.Categories().Resolve(context.Background(), NewSkillsProfile("reviews", []skills.SkillReference{{
		Source: GlobalSourceDevinConfig, RelativePath: "review",
	}}))
	if err != nil {
		t.Fatal(err)
	}
	return adapterLaunchApplication{
		adapter: adapter, resolved: resolved, sessionsDirectory: fixture.sessionsDirectory,
		workingDirectory: workingDirectory,
		terminal:         launch.Terminal{Input: input, Output: output, ErrorOutput: errorOutput},
	}
}

func (application adapterLaunchApplication) Run(ctx context.Context, _ []string) int {
	exitCode, err := application.adapter.Launch(
		ctx, application.sessionsDirectory, application.workingDirectory,
		application.resolved, application.terminal,
	)
	if err != nil {
		fmt.Fprintln(application.terminal.ErrorOutput, err)
		return 1
	}
	return exitCode
}

type recordingSandbox struct {
	delegate  launch.ProcessSandbox
	arguments [][]string
}

func (sandbox *recordingSandbox) Check(ctx context.Context, request launch.SandboxCheck) error {
	return sandbox.delegate.Check(ctx, request)
}

func (sandbox *recordingSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.arguments = append(sandbox.arguments, append([]string(nil), request.Arguments...))
	return sandbox.delegate.Prepare(ctx, request)
}

type failingSandbox struct {
	checkErr   error
	prepareErr error
}

func (sandbox failingSandbox) Check(context.Context, launch.SandboxCheck) error {
	return sandbox.checkErr
}

func (sandbox failingSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	return nil, sandbox.prepareErr
}

type startupQuarantineSandbox struct {
	delegate    launch.ProcessSandbox
	cleanupDone chan struct{}
	sessionRoot string
}

func (sandbox *startupQuarantineSandbox) Check(ctx context.Context, request launch.SandboxCheck) error {
	return sandbox.delegate.Check(ctx, request)
}

func (sandbox *startupQuarantineSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	if len(request.Arguments) != 0 {
		return sandbox.delegate.Prepare(ctx, request)
	}
	sandbox.sessionRoot = request.SessionDirectory
	return startupQuarantineProcess{cleanupDone: sandbox.cleanupDone}, nil
}

type startupQuarantineProcess struct {
	cleanupDone <-chan struct{}
}

func (process startupQuarantineProcess) Start() error {
	return fmt.Errorf("startup cleanup quarantined")
}
func (startupQuarantineProcess) Wait() error { return nil }
func (startupQuarantineProcess) Signal(os.Signal) error {
	return nil
}
func (process startupQuarantineProcess) CleanupDone() <-chan struct{} { return process.cleanupDone }

type startAttachRaceProcess struct {
	preflightContext context.Context
	mutex            sync.Mutex
	signals          []syscall.Signal
}

func (process *startAttachRaceProcess) Start() error {
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-process.preflightContext.Done():
		// CommandContext cancellation can stop a just-started process before
		// the supervisor replays its pending terminating signal.
		_ = process.Signal(syscall.SIGKILL)
	case <-time.After(200 * time.Millisecond):
	}
	return nil
}

func (*startAttachRaceProcess) Wait() error { return nil }

func (process *startAttachRaceProcess) Signal(signal os.Signal) error {
	unixSignal, ok := signal.(syscall.Signal)
	if !ok {
		return nil
	}
	process.mutex.Lock()
	defer process.mutex.Unlock()
	process.signals = append(process.signals, unixSignal)
	return nil
}

func (process *startAttachRaceProcess) receivedSignals() []syscall.Signal {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	return append([]syscall.Signal(nil), process.signals...)
}

func writeFakeDevin(t *testing.T, script string) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "devin")
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return binaryPath
}

func successfulDevinScript(interactiveBody string) string {
	return `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'Logged in (via fixture).\n'
  exit 0
fi
` + interactiveBody
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q", path)
}

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type authorityTestContribution struct{}

func (authorityTestContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (authorityTestContribution) Materialize(string) error                         { return nil }
func (authorityTestContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func TestRunShellUsesOneResolvedPlanForCheckAndProcess(t *testing.T) {
	sandbox := &fakeSandbox{process: &fakeProcess{}}
	plan := authority.New([]authority.Contribution{{ID: "test", Value: authorityTestContribution{}}}, launch.WorkspaceAccessReadOnly, 3, "")
	err := newExecutor(sandbox).RunShell(context.Background(), ShellRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(),
		WorkspaceAccess: launch.WorkspaceAccessReadWrite, ResolvedPlan: &plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.check.WorkspaceAccess != launch.WorkspaceAccessReadOnly || sandbox.request.WorkspaceAccess != launch.WorkspaceAccessReadOnly {
		t.Fatalf("resolved authority drifted: check=%q process=%q", sandbox.check.WorkspaceAccess, sandbox.request.WorkspaceAccess)
	}
}

type fakeSandbox struct {
	process              *fakeProcess
	checkErr, prepareErr error
	checks, prepares     int
	request              launch.ProcessRequest
	check                launch.SandboxCheck
	inspect              func(launch.ProcessRequest) error
	checkFn              func() error
}

type invalidPreparedProcessSandbox struct {
	typedNil bool
	prepares int
}

func (*invalidPreparedProcessSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{Supported: true, Ready: true}, nil
}
func (*invalidPreparedProcessSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (sandbox *invalidPreparedProcessSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	sandbox.prepares++
	if sandbox.typedNil {
		var process *invalidPreparedProcess
		return process, nil
	}
	return nil, nil
}

type invalidPreparedProcess struct{}

func (*invalidPreparedProcess) Start() error { panic("invalid prepared process was started") }
func (*invalidPreparedProcess) Wait() error  { panic("invalid prepared process was waited") }
func (*invalidPreparedProcess) Signal(os.Signal) error {
	panic("invalid prepared process was signaled")
}

func invalidPreparedProcessCases() []struct {
	name     string
	typedNil bool
} {
	return []struct {
		name     string
		typedNil bool
	}{{name: "nil"}, {name: "typed-nil", typedNil: true}}
}

func requireSandboxSetupFailure(t *testing.T, err error) {
	t.Helper()
	var failure *launch.SandboxError
	if !errors.As(err, &failure) || failure.Category != launch.SandboxSetupFailed {
		t.Fatalf("error = %T %v, want sanitized sandbox setup failure", err, err)
	}
}

func TestRunShellRejectsInvalidPreparedProcess(t *testing.T) {
	for _, test := range invalidPreparedProcessCases() {
		t.Run(test.name, func(t *testing.T) {
			sessions := filepath.Join(t.TempDir(), "sessions")
			sandbox := &invalidPreparedProcessSandbox{typedNil: test.typedNil}
			err := newExecutor(sandbox).RunShell(context.Background(), ShellRequest{
				SessionsDirectory: sessions, WorkingDirectory: t.TempDir(),
			})
			requireSandboxSetupFailure(t, err)
			if sandbox.prepares != 1 {
				t.Fatalf("prepare calls = %d, want 1", sandbox.prepares)
			}
			if entries, err := os.ReadDir(sessions); err != nil || len(entries) != 0 {
				t.Fatalf("invalid prepared process retained shell Session: %v %v", entries, err)
			}
		})
	}
}

func TestRunDevinProbeRejectsInvalidPreparedProcess(t *testing.T) {
	for _, test := range invalidPreparedProcessCases() {
		t.Run(test.name, func(t *testing.T) {
			sessions := filepath.Join(t.TempDir(), "sessions")
			sandbox := &invalidPreparedProcessSandbox{typedNil: test.typedNil}
			code, err := newExecutor(sandbox).RunDevin(context.Background(), DevinRequest{
				SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Executable: "devin",
				ExpectedCatalog: []skills.SkillReference{},
			})
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			requireSandboxSetupFailure(t, err)
			if sandbox.prepares != 1 {
				t.Fatalf("prepare calls = %d, want only the Skills probe", sandbox.prepares)
			}
			if entries, err := os.ReadDir(sessions); err != nil || len(entries) != 0 {
				t.Fatalf("invalid prepared process retained Devin Session: %v %v", entries, err)
			}
		})
	}
}

// TestRunDevinOwnsBothPreflightsAndTheSessionLease exercises the real
// executor lifecycle, not an adapter callback.  The first two processes are
// the fixed catalog/auth probes and the third is the fixed interactive target.
func TestRunDevinOwnsBothPreflightsAndTheSessionLease(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions")
	home := filepath.Join(sessions, "unused")
	processes := []*fakeProcess{
		{waitFn: func() error { return nil }},
		{waitFn: func() error { return nil }},
		{},
	}
	var requests []launch.ProcessRequest
	sandbox := &sequenceSandbox{processes: processes, requests: &requests}
	request := DevinRequest{
		SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Executable: "caller-must-not-select",
		RuntimeInputs: []string{"caller-runtime-must-not-be-granted"}, ExistingHomeDirectory: filepath.Join(t.TempDir(), "caller-home"),
		ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	}
	plan := authority.New([]authority.Contribution{{ID: "test", Value: authorityTestContribution{}}}, launch.WorkspaceAccessReadOnly, 3, "devin", authority.TargetRequirements{Recipe: authority.RecipeDevin, Executable: "devin", RuntimeInputs: []string{"registered-runtime"}, ExistingHomeDirectory: filepath.Join(t.TempDir(), "registered-home")})
	request.ResolvedPlan = &plan
	// The catalog interpreter accepts an empty JSON catalog; write the probe
	// outputs through the request terminals as the real contained processes do.
	processes[0].write = []byte("[]\n")
	processes[1].write = []byte("Logged in\n")
	if code, err := newExecutor(sandbox).RunDevin(context.Background(), request); err != nil || code != 0 {
		t.Fatalf("RunDevin = (%d, %v)", code, err)
	}
	if got := [][]string{requests[0].Arguments, requests[1].Arguments, requests[2].Arguments}; !reflect.DeepEqual(got, [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}}) {
		t.Fatalf("fixed Devin lifecycle arguments = %#v", got)
	}
	for index, prepared := range requests {
		if prepared.WorkspaceAccess != launch.WorkspaceAccessReadOnly {
			t.Fatalf("process %d workspace access = %q", index, prepared.WorkspaceAccess)
		}
		if prepared.Executable != "devin" || !reflect.DeepEqual(prepared.RuntimeInputs, []string{"registered-runtime"}) {
			t.Fatalf("process %d did not use registered target requirements: %#v", index, prepared)
		}
	}
	if entries, err := os.ReadDir(sessions); err != nil || len(entries) != 0 {
		t.Fatalf("executor did not remove settled Devin Session: %v %v", entries, err)
	}
	_ = home
}

func (*fakeSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (s *fakeSandbox) Check(_ context.Context, check launch.SandboxCheck) error {
	s.checks++
	s.check = check
	if s.checkFn != nil {
		return s.checkFn()
	}
	return s.checkErr
}
func (s *fakeSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	s.prepares++
	s.request = request
	if s.inspect != nil {
		if err := s.inspect(request); err != nil {
			return nil, err
		}
	}
	if s.prepareErr != nil {
		return nil, s.prepareErr
	}
	return s.process, nil
}

type fakeProcess struct {
	starts, waits     int
	startErr, waitErr error
	cleanup           <-chan struct{}
	waited            chan<- struct{}
	write             []byte
	output            io.Writer
	waitFn            func() error
	startEntered      chan<- struct{}
	startReturned     chan<- struct{}
	allowStart        <-chan struct{}
	signalErr         error
	signals           int
}

func (p *fakeProcess) Start() error {
	p.starts++
	if p.startEntered != nil {
		p.startEntered <- struct{}{}
	}
	if p.allowStart != nil {
		<-p.allowStart
	}
	if p.startReturned != nil {
		p.startReturned <- struct{}{}
	}
	return p.startErr
}
func (p *fakeProcess) Wait() error {
	p.waits++
	if len(p.write) != 0 && p.output != nil {
		_, _ = p.output.Write(p.write)
	}
	if p.waited != nil {
		p.waited <- struct{}{}
	}
	if p.waitFn != nil {
		return p.waitFn()
	}
	return p.waitErr
}
func (p *fakeProcess) Signal(os.Signal) error {
	p.signals++
	return p.signalErr
}
func (p *fakeProcess) CleanupDone() <-chan struct{} { return p.cleanup }

type sequenceSandbox struct {
	processes []*fakeProcess
	requests  *[]launch.ProcessRequest
}

func (*sequenceSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (*sequenceSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (s *sequenceSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	*s.requests = append(*s.requests, request)
	index := len(*s.requests) - 1
	if index >= len(s.processes) {
		return nil, errors.New("unexpected Devin process")
	}
	s.processes[index].output = request.Terminal.Output
	return s.processes[index], nil
}

func shellRequest(t *testing.T, sessions string) ShellRequest {
	t.Helper()
	return ShellRequest{SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
}

func exit23(t *testing.T) error {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "exit 23").Run()
	if err == nil {
		t.Fatal("exit fixture unexpectedly succeeded")
	}
	return err
}

func TestRunShellUsesFixedCommandAndCleansMaterializedSession(t *testing.T) {
	p := &fakeProcess{}
	s := &fakeSandbox{process: p}
	var materialized string
	req := shellRequest(t, filepath.Join(t.TempDir(), "sessions"))
	req.Materializer = materializerFunc(func(home string) error {
		materialized = home
		return os.WriteFile(filepath.Join(home, "marker"), []byte("ok"), 0o600)
	})
	s.inspect = func(request launch.ProcessRequest) error {
		if _, err := os.Stat(filepath.Join(request.SessionHome, ".local", "share", "devin", "credentials.toml")); !os.IsNotExist(err) {
			return errors.New("credential unexpectedly present in shell Session")
		}
		if _, err := os.Stat(filepath.Join(request.SessionHome, "marker")); err != nil {
			return err
		}
		return nil
	}
	if err := newExecutor(s).RunShell(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if s.check.Executable != systemShell || len(s.check.RuntimeInputs) != 0 || s.request.Executable != systemShell || !reflect.DeepEqual(s.request.Arguments, []string{"-f"}) {
		t.Fatalf("fixed shell request = check %#v prepare %#v", s.check, s.request)
	}
	if _, err := os.Stat(filepath.Join(materialized, "marker")); !os.IsNotExist(err) {
		t.Fatalf("completed shell Session remains: %v", err)
	}
	if p.starts != 1 || p.waits != 1 {
		t.Fatalf("lifecycle starts=%d waits=%d", p.starts, p.waits)
	}
}

func TestRunShellOrdinaryExitAfterCleanupProof(t *testing.T) {
	p := &fakeProcess{waitErr: exit23(t)}
	sessions := filepath.Join(t.TempDir(), "sessions")
	err := newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, sessions))
	var targetExit *exec.ExitError
	if !errors.As(err, &targetExit) || targetExit.ExitCode() != 23 || p.waits != 1 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
	eventuallyEmptyDirectory(t, sessions)
}

func TestCleanupPrecedenceDoesNotExposeExitCodeBearingOutcome(t *testing.T) {
	cleanup := &launch.SandboxError{Category: launch.SandboxProcessWaitFailed}
	err := cleanupPrecedence(&shellExit{code: 23}, cleanup)
	var exitCoder interface{ ExitCode() int }
	if !errors.As(err, &cleanup) || errors.As(err, &exitCoder) {
		t.Fatalf("cleanup precedence result=%v", err)
	}
}

func TestRunShellCleanupUncertaintyOutranksOrdinaryExitAndRetainsSession(t *testing.T) {
	done := make(chan struct{})
	p := &fakeProcess{waitErr: exit23(t), cleanup: done}
	sessions := filepath.Join(t.TempDir(), "sessions")
	start := time.Now()
	err := newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, sessions))
	if time.Since(start) < 4*time.Second {
		t.Fatal("pending cleanup did not use bounded cleanup settlement")
	}
	var targetExit *exec.ExitError
	var sandboxErr *launch.SandboxError
	if errors.As(err, &targetExit) || !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxProcessWaitFailed || p.waits != 1 {
		t.Fatalf("cleanup precedence result=%v waits=%d", err, p.waits)
	}
	entries, readErr := os.ReadDir(sessions)
	if readErr != nil || len(entries) == 0 {
		t.Fatalf("uncertain Session was removed: %v %v", entries, readErr)
	}
	close(done)
	eventuallyEmptyDirectory(t, sessions)
}

func TestRunShellFailedStartDoesNotWaitRetainsThenRemovesSession(t *testing.T) {
	done := make(chan struct{})
	defer func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}()
	process := &fakeProcess{startErr: errors.New("start failed"), cleanup: done}
	sessions := filepath.Join(t.TempDir(), "sessions")
	// Returning from the actual bounded settlement proves Start already failed.
	// Keep cleanup withheld through that return, not merely directory creation.
	err := newExecutor(&fakeSandbox{process: process}).RunShell(context.Background(), shellRequest(t, sessions))
	var failure *launch.SandboxError
	if !errors.As(err, &failure) || failure.Category != launch.SandboxProcessWaitFailed {
		t.Fatalf("result = %v, want uncertain cleanup to take precedence", err)
	}
	if process.starts != 1 || process.waits != 0 {
		t.Fatalf("Start/Wait = %d/%d, want 1/0", process.starts, process.waits)
	}
	entries, readErr := os.ReadDir(sessions)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("uncertain Session was removed: %v %v", entries, readErr)
	}
	close(done)
	eventuallyEmptyDirectory(t, sessions)
}

func TestDevinSignalSupervisorCancelsEarlySignalBeforeStart(t *testing.T) {
	canceled := make(chan struct{})
	s := newDevinSignalSupervisor(func() { close(canceled) })
	defer s.stop()
	s.forwarded <- syscall.SIGTERM
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("early signal did not cancel preflight")
	}
	p := &fakeProcess{}
	if err := runDevinAttached(p, s); err == nil || p.starts != 0 || p.waits != 0 {
		t.Fatalf("early signal result=%v Start/Wait=%d/%d", err, p.starts, p.waits)
	}
}

func TestInteractiveReservationRejectsPendingTerminationBeforePrepare(t *testing.T) {
	supervisor := newDevinSignalSupervisor(func() {})
	defer supervisor.stop()
	supervisor.forwarded <- syscall.SIGTERM
	waitForPendingSignal(t, supervisor, syscall.SIGTERM)
	sandbox := &fakeSandbox{process: &fakeProcess{}}
	created, err := session.Create(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	request := DevinRequest{SessionsDirectory: filepath.Join(t.TempDir(), "unused"), WorkingDirectory: t.TempDir(), Executable: "devin", Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
	if _, err := newExecutor(sandbox).prepareDevinInteractive(context.Background(), created, request, supervisor); err == nil {
		t.Fatal("interactive preparation succeeded after a pending terminating signal")
	}
	if sandbox.prepares != 0 || sandbox.process.starts != 0 || sandbox.process.waits != 0 {
		t.Fatalf("Prepare/Start/Wait = %d/%d/%d, want 0/0/0", sandbox.prepares, sandbox.process.starts, sandbox.process.waits)
	}
}

func TestInteractivePreparationFailureEndsReservationWithoutStart(t *testing.T) {
	canceled := make(chan struct{})
	supervisor := newDevinSignalSupervisor(func() { close(canceled) })
	defer supervisor.stop()
	sandbox := &fakeSandbox{process: &fakeProcess{}, prepareErr: errors.New("prepare failed")}
	created, err := session.Create(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	request := DevinRequest{SessionsDirectory: filepath.Join(t.TempDir(), "unused"), WorkingDirectory: t.TempDir(), Executable: "devin", Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
	if _, err := newExecutor(sandbox).prepareDevinInteractive(context.Background(), created, request, supervisor); err == nil {
		t.Fatal("interactive preparation unexpectedly succeeded")
	}
	if sandbox.prepares != 1 || sandbox.process.starts != 0 || sandbox.process.waits != 0 {
		t.Fatalf("Prepare/Start/Wait = %d/%d/%d, want 1/0/0", sandbox.prepares, sandbox.process.starts, sandbox.process.waits)
	}
	supervisor.forwarded <- syscall.SIGTERM
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("preparation failure left the interactive reservation active")
	}
}

func TestInteractiveSignalAfterRetentionBeforeStartReplaysAndReleasesSession(t *testing.T) {
	for _, cleanup := range []struct {
		name       string
		done       chan struct{}
		retainLate bool
	}{
		{name: "nil cleanup channel"},
		{name: "open cleanup channel", done: make(chan struct{}), retainLate: true},
	} {
		t.Run(cleanup.name, func(t *testing.T) {
			sessions := filepath.Join(t.TempDir(), "sessions")
			created, err := session.Create(sessions, t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			credential := filepath.Join(created.HomeDirectory(), ".local", "share", "devin", "credentials.toml")
			if err := os.MkdirAll(filepath.Dir(credential), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(credential, []byte("token = \"fixture\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			process := &fakeProcess{cleanup: cleanup.done}
			supervisor := newDevinSignalSupervisor(func() {})
			defer supervisor.stop()
			request := DevinRequest{SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Executable: "devin", Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}

			retained, err := newExecutor(&fakeSandbox{process: process}).prepareDevinInteractive(context.Background(), created, request, supervisor)
			if err != nil {
				t.Fatal(err)
			}
			supervisor.forwarded <- syscall.SIGTERM
			waitForPendingSignal(t, supervisor, syscall.SIGTERM)
			if err := runDevinAttachedReserved(retained, supervisor); err != nil {
				t.Fatal(err)
			}
			if process.starts != 1 || process.waits != 1 || process.signals != 1 {
				t.Fatalf("Start/Wait/Signal = %d/%d/%d, want 1/1/1", process.starts, process.waits, process.signals)
			}
			if err := created.Remove(); err != nil {
				t.Fatal(err)
			}
			if cleanup.retainLate {
				if _, err := os.Stat(created.RootDirectory()); err != nil {
					t.Fatalf("Session was removed before late cleanup proof: %v", err)
				}
				close(cleanup.done)
				eventuallyRemovedSession(t, created.RootDirectory())
				return
			}
			if _, err := os.Stat(created.RootDirectory()); !os.IsNotExist(err) {
				t.Fatalf("retained credential Session remains after settled target: %v", err)
			}
		})
	}
}

func eventuallyRemovedSession(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Session remained after late cleanup proof")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRunDevinAttachedWaitsOnceAfterReplayFailure(t *testing.T) {
	s := newDevinSignalSupervisor(func() {})
	defer s.stop()
	entered, release := make(chan struct{}), make(chan struct{})
	p := &fakeProcess{startEntered: entered, allowStart: release, signalErr: errors.New("private replay failure")}
	result := make(chan error, 1)
	go func() { result <- runDevinAttached(p, s) }()
	<-entered
	s.forwarded <- syscall.SIGTERM
	deadline := time.Now().Add(time.Second)
	for {
		s.mutex.Lock()
		pending := s.pending
		s.mutex.Unlock()
		if pending == syscall.SIGTERM {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signal was not captured during Start")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	err := <-result
	var sandboxErr *launch.SandboxError
	if !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxProcessStartFailed || p.waits != 1 || strings.Contains(err.Error(), "private") {
		t.Fatalf("replay result=%v waits=%d", err, p.waits)
	}
}

func TestRunShellFailedWaitRetainsThenRemovesSession(t *testing.T) {
	done := make(chan struct{})
	waited := make(chan struct{}, 1)
	p := &fakeProcess{waitErr: errors.New("wait failed"), cleanup: done, waited: waited}
	sessions := filepath.Join(t.TempDir(), "sessions")
	result := make(chan error, 1)
	go func() {
		result <- newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, sessions))
	}()
	<-waited
	eventuallyNonEmptyDirectory(t, sessions)
	close(done)
	if err := <-result; err == nil || p.waits != 1 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
	eventuallyEmptyDirectory(t, sessions)
}

func TestRunShellSuccessfulWaitRetainsThenRemovesSession(t *testing.T) {
	done := make(chan struct{})
	waited := make(chan struct{}, 1)
	p := &fakeProcess{cleanup: done, waited: waited}
	sessions := filepath.Join(t.TempDir(), "sessions")
	result := make(chan error, 1)
	go func() {
		result <- newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, sessions))
	}()
	<-waited
	eventuallyNonEmptyDirectory(t, sessions)
	close(done)
	if err := <-result; err != nil || p.waits != 1 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
	eventuallyEmptyDirectory(t, sessions)
}

func eventuallyNonEmptyDirectory(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		entries, err := os.ReadDir(path)
		if err == nil && len(entries) != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Session was not retained: %v %v", entries, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func eventuallyEmptyDirectory(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		entries, err := os.ReadDir(path)
		if err == nil && len(entries) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Session remained after cleanup proof: %v %v", entries, err)
		}
		time.Sleep(time.Millisecond)
	}
}

type materializerFunc func(string) error

func (f materializerFunc) Materialize(home string) error { return f(home) }

type shellExit struct{ code int }

func (e *shellExit) Error() string { return "shell exit" }
func (e *shellExit) ExitCode() int { return e.code }

func TestRunDevinProjectsOnlyAllowlistedCredentialAndSelectedFiles(t *testing.T) {
	source := t.TempDir()
	for _, relative := range []string{
		".local/share/devin/credentials.toml", ".config/devin/config.json", ".config/devin/mcp_config.json", ".config/devin/hooks/hook", ".config/devin/AGENTS.md",
	} {
		path := filepath.Join(source, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var inspected bool
	process := &fakeProcess{}
	sandbox := &fakeSandbox{process: process}
	sandbox.inspect = func(request launch.ProcessRequest) error {
		credential := filepath.Join(request.SessionHome, ".local", "share", "devin", "credentials.toml")
		contents, err := os.ReadFile(credential)
		if err != nil || string(contents) != "fixture-only" {
			t.Fatalf("allowlisted fixture was not projected: %v", err)
		}
		info, err := os.Stat(credential)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("credential mode was not private: %v", err)
		}
		for _, relative := range []string{"config.json", "mcp_config.json", "hooks", "AGENTS.md"} {
			if _, err := os.Lstat(filepath.Join(request.SessionHome, ".config", "devin", relative)); !os.IsNotExist(err) {
				t.Fatalf("unrestricted state %s was projected: %v", relative, err)
			}
		}
		for _, source := range []string{".config/devin/skills/selected", ".agents/skills/selected"} {
			for _, relative := range []string{"SKILL.md", "references/proof.txt"} {
				if _, err := os.Stat(filepath.Join(request.SessionHome, filepath.FromSlash(source), filepath.FromSlash(relative))); err != nil {
					t.Fatal(err)
				}
			}
		}
		inspected = true
		// The inspection occurs at the first real Prepare, after materialization
		// and credential copy. Stop there without introducing a fake probe result.
		return &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	request := DevinRequest{SessionsDirectory: t.TempDir(), WorkingDirectory: t.TempDir(), ExistingHomeDirectory: source, Executable: "fixture-devin"}
	request.Materializer = materializerFunc(func(home string) error {
		for _, directory := range []string{".config/devin/skills/selected", ".agents/skills/selected"} {
			if err := os.CopyFS(filepath.Join(home, filepath.FromSlash(directory)), os.DirFS(filepath.Join("..", "adapter", "devin", "testdata", "selected-skill"))); err != nil {
				return err
			}
		}
		return nil
	})
	code, err := newExecutor(sandbox).RunDevin(context.Background(), request)
	if !inspected || code != 1 || err == nil || process.starts != 0 {
		t.Fatalf("inspection result = %t, %d, %v", inspected, code, err)
	}
	eventuallyEmptyDirectory(t, request.SessionsDirectory)
}

func TestRunShellCheckFailurePrecedesSessionMaterialization(t *testing.T) {
	failure := &launch.SandboxError{Category: launch.SandboxBackendUnavailable}
	sandbox := &fakeSandbox{checkErr: failure}
	sessions := filepath.Join(t.TempDir(), "sessions")
	request := shellRequest(t, sessions)
	materialized := false
	request.Materializer = materializerFunc(func(string) error { materialized = true; return nil })
	err := newExecutor(sandbox).RunShell(context.Background(), request)
	if err != failure || materialized || sandbox.request.SessionDirectory != "" {
		t.Fatalf("failed check advanced lifecycle: %v, materialized=%t", err, materialized)
	}
	if _, err := os.Stat(sessions); !os.IsNotExist(err) {
		t.Fatalf("failed check created Sessions directory: %v", err)
	}
}

func TestRunShellPreparationFailureRemovesMaterializedSession(t *testing.T) {
	failure := &launch.SandboxError{Category: launch.SandboxSetupFailed}
	sandbox := &fakeSandbox{prepareErr: failure}
	sessions := filepath.Join(t.TempDir(), "sessions")
	request := shellRequest(t, sessions)
	materialized := false
	request.Materializer = materializerFunc(func(home string) error {
		materialized = true
		return os.WriteFile(filepath.Join(home, "SKILL.md"), []byte("selected fixture"), 0600)
	})
	sandbox.inspect = func(request launch.ProcessRequest) error {
		if !materialized {
			t.Fatal("Prepare preceded materialization")
		}
		contents, err := os.ReadFile(filepath.Join(request.SessionHome, "SKILL.md"))
		if err != nil || string(contents) != "selected fixture" {
			t.Fatalf("Prepare did not receive selected materialization: %v", err)
		}
		return nil
	}
	if err := newExecutor(sandbox).RunShell(context.Background(), request); err != failure {
		t.Fatalf("preparation error changed: %v", err)
	}
	if !materialized || sandbox.request.SessionDirectory == "" {
		t.Fatal("preparation boundary was not reached")
	}
	eventuallyEmptyDirectory(t, sessions)
}

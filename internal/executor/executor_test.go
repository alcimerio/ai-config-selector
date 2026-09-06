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

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type fakeSandbox struct {
	process              *fakeProcess
	checkErr, prepareErr error
	request              launch.ProcessRequest
	check                launch.SandboxCheck
	inspect              func(launch.ProcessRequest) error
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
		SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Executable: "devin",
		ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	}
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
	if entries, err := os.ReadDir(sessions); err != nil || len(entries) != 0 {
		t.Fatalf("executor did not remove settled Devin Session: %v %v", entries, err)
	}
	_ = home
}

func (*fakeSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (s *fakeSandbox) Check(_ context.Context, check launch.SandboxCheck) error {
	s.check = check
	return s.checkErr
}
func (s *fakeSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
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
func (p *fakeProcess) Signal(os.Signal) error       { return p.signalErr }
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
	err := newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, filepath.Join(t.TempDir(), "sessions")))
	var targetExit *exec.ExitError
	if !errors.As(err, &targetExit) || targetExit.ExitCode() != 23 || p.waits != 1 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
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
	startReturned := make(chan struct{})
	p := &fakeProcess{startErr: errors.New("start failed"), cleanup: done, startReturned: startReturned}
	sessions := filepath.Join(t.TempDir(), "sessions")
	result := make(chan error, 1)
	go func() {
		result <- newExecutor(&fakeSandbox{process: p}).RunShell(context.Background(), shellRequest(t, sessions))
	}()
	select {
	case <-startReturned:
	case <-time.After(time.Second):
		t.Fatal("Start did not fail")
	}
	eventuallyNonEmptyDirectory(t, sessions)
	select {
	case err := <-result:
		t.Fatalf("failed Start returned before cleanup proof: %v", err)
	default:
	}
	close(done)
	if err := <-result; err == nil || p.waits != 0 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
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

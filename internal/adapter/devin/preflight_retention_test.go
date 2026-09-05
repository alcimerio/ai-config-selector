package devin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestLaunchPreflightsRetainSessionUntilCleanupIsProven(t *testing.T) {
	for _, stage := range []string{"skills", "auth"} {
		for _, failure := range []string{"start", "wait", "none"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				t.Parallel()
				fixture := newLaunchTestFixture(t)
				sandbox := &preflightRetentionSandbox{
					stage: stage, failure: failure, cleanupDone: make(chan struct{}),
				}
				fixture.sandbox = sandbox
				application := fixture.application(t, "/test/devin", t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
				t.Cleanup(func() {
					sandbox.finishCleanup()
					if sandbox.guard != nil {
						defer sandbox.guard.Close()
						waitForPreflightSessionRemoval(t, sandbox)
					}
				})

				exitCode, err := application.adapter.Launch(context.Background(), application.sessionsDirectory,
					application.workingDirectory, application.resolved, application.terminal)
				if sandbox.root == "" {
					t.Fatal("the selected preflight was not prepared")
				}
				if _, statErr := os.Stat(sandbox.root); statErr != nil {
					t.Fatalf("Session removed before preflight cleanup was proven: %v", statErr)
				}
				var sandboxErr *launch.SandboxError
				if exitCode != 1 || !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxProcessWaitFailed {
					t.Fatalf("launch result = (%d, %v), want cleanup failure to supersede the probe result", exitCode, err)
				}
				for _, private := range []string{sandbox.root, "PRIVATE_PREFLIGHT_FAILURE", "PRIVATE_PREFLIGHT_OUTPUT"} {
					if strings.Contains(err.Error(), private) {
						t.Fatalf("preflight cleanup diagnostic exposed %q: %v", private, err)
					}
				}
				wantStages := []string{"skills"}
				if stage == "auth" {
					wantStages = append(wantStages, "auth")
				}
				if !reflect.DeepEqual(sandbox.stages, wantStages) {
					t.Fatalf("prepared stages = %v, want %v; execution advanced past unsettled cleanup", sandbox.stages, wantStages)
				}
				wantWaits := 1
				if failure == "start" {
					wantWaits = 0
				}
				if sandbox.process.starts != 1 || sandbox.process.waits != wantWaits {
					t.Fatalf("probe Start/Wait calls = %d/%d, want 1/%d", sandbox.process.starts, sandbox.process.waits, wantWaits)
				}

				concurrent, createErr := launch.CreateSession(fixture.sessionsDirectory)
				if createErr != nil {
					t.Fatal(createErr)
				}
				t.Cleanup(func() {
					if removeErr := concurrent.Remove(); removeErr != nil {
						t.Error(removeErr)
					}
				})
				if _, statErr := os.Stat(sandbox.root); statErr != nil {
					t.Fatalf("concurrent startup reclaimed the unsettled preflight Session: %v", statErr)
				}

				sandbox.finishCleanup()
				waitForPreflightSessionRemoval(t, sandbox)
			})
		}
	}
}

func TestLaunchPreflightsPreserveFailureAfterProvenCleanup(t *testing.T) {
	for _, stage := range []string{"skills", "auth"} {
		for _, failure := range []string{"start", "wait"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				fixture := newLaunchTestFixture(t)
				sandbox := &preflightRetentionSandbox{
					stage: stage, failure: failure, cleanupDone: make(chan struct{}),
				}
				sandbox.finishCleanup()
				t.Cleanup(func() {
					if sandbox.guard != nil {
						_ = sandbox.guard.Close()
					}
				})
				fixture.sandbox = sandbox
				application := fixture.application(t, "/test/devin", t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
				exitCode, err := application.adapter.Launch(context.Background(), application.sessionsDirectory,
					application.workingDirectory, application.resolved, application.terminal)
				if exitCode != 1 || err == nil {
					t.Fatalf("launch result = (%d, %v), want preflight failure", exitCode, err)
				}
				for _, private := range []string{sandbox.root, "PRIVATE_PREFLIGHT_FAILURE", "PRIVATE_PREFLIGHT_OUTPUT"} {
					if strings.Contains(err.Error(), private) {
						t.Fatalf("settled preflight diagnostic exposed %q: %v", private, err)
					}
				}
				if failure == "start" {
					var sandboxErr *launch.SandboxError
					if !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxProcessStartFailed {
						t.Fatalf("settled Start error = %v, want process_start_failed", err)
					}
				} else {
					var preflightErr *PreflightError
					want := CapabilitySkillIsolation
					if stage == "auth" {
						want = CapabilityAuthentication
					}
					if !errors.As(err, &preflightErr) || preflightErr.Capability != want {
						t.Fatalf("settled Wait error = %v, want %s preflight failure", err, want)
					}
				}
				if _, statErr := os.Stat(sandbox.root); !os.IsNotExist(statErr) {
					t.Fatalf("settled preflight left its Session behind: %v", statErr)
				}
			})
		}
	}
}

func TestPreflightRejectsMissingSessionRetentionBeforePreparingProcess(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	sandbox := &preflightRetentionSandbox{}
	fixture.sandbox = sandbox
	application := fixture.application(t, "/test/devin", t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	err := application.adapter.verifyAuthentication(context.Background(), &Session{WorkingDirectory: application.workingDirectory})
	var sandboxErr *launch.SandboxError
	if !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxSetupFailed {
		t.Errorf("missing retention error = %v, want setup_failed", err)
	}
	if len(sandbox.stages) != 0 {
		t.Fatalf("prepared %v without Session retention", sandbox.stages)
	}
}

type preflightRetentionSandbox struct {
	stage       string
	failure     string
	cleanupDone chan struct{}
	cleanupOnce sync.Once
	root        string
	guardPath   string
	guard       *os.File
	stages      []string
	process     *preflightRetentionProcess
}

func (sandbox *preflightRetentionSandbox) finishCleanup() {
	sandbox.cleanupOnce.Do(func() { close(sandbox.cleanupDone) })
}

func (*preflightRetentionSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return directSandbox{}.Readiness(context.Background())
}

func (*preflightRetentionSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }

func (sandbox *preflightRetentionSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	stage := request.Arguments[0]
	sandbox.stages = append(sandbox.stages, stage)
	process := &preflightRetentionProcess{output: request.Terminal.Output, stage: stage, home: request.SessionHome}
	if stage == sandbox.stage {
		sandbox.root = request.SessionDirectory
		// Observe the existing lease inode so the test can await its final
		// unlock, which follows removal and directory sync, before teardown.
		sandbox.guardPath = filepath.Join(request.SessionsDirectory+".leases", filepath.Base(sandbox.root)+".lock")
		var err error
		sandbox.guard, err = os.Open(sandbox.guardPath)
		if err != nil {
			return nil, err
		}
		process.failure, process.cleanupDone = sandbox.failure, sandbox.cleanupDone
		sandbox.process = process
	}
	return process, nil
}

type preflightRetentionProcess struct {
	stage       string
	home        string
	failure     string
	output      io.Writer
	cleanupDone <-chan struct{}
	starts      int
	waits       int
}

func (process *preflightRetentionProcess) Start() error {
	process.starts++
	if process.failure == "start" {
		return &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	return nil
}

func (process *preflightRetentionProcess) Wait() error {
	process.waits++
	if process.failure == "wait" {
		_, _ = io.WriteString(process.output, "PRIVATE_PREFLIGHT_OUTPUT")
		return errors.New("PRIVATE_PREFLIGHT_FAILURE")
	}
	switch process.stage {
	case "skills":
		return json.NewEncoder(process.output).Encode([]observedSkill{{
			Name: "review", Provider: "Devin", BaseDir: filepath.Join(process.home, ".config", "devin", "skills", "review"),
		}})
	case "auth":
		_, err := io.WriteString(process.output, "Logged in (via fixture).\n")
		return err
	default:
		return errors.New("interactive launch must not follow an unsettled preflight")
	}
}

func (*preflightRetentionProcess) Signal(os.Signal) error               { return nil }
func (process *preflightRetentionProcess) CleanupDone() <-chan struct{} { return process.cleanupDone }

func waitForPreflightSessionRemoval(t *testing.T, sandbox *preflightRetentionSandbox) {
	t.Helper()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for {
		if err := syscall.Flock(int(sandbox.guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			defer syscall.Flock(int(sandbox.guard.Fd()), syscall.LOCK_UN)
			for _, path := range []string{sandbox.root, sandbox.guardPath} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("preflight lease released before removing %q: %v", path, err)
				}
			}
			return
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatal(err)
		}
		select {
		case <-timeout.C:
			t.Fatal("Session remained after preflight cleanup was proven")
		case <-poll.C:
		}
	}
}

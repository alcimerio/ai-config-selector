package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type environmentExecutionContribution struct{ intents []launch.EnvironmentIntent }

func (environmentExecutionContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (environmentExecutionContribution) Materialize(string) error                         { return nil }
func (environmentExecutionContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}
func (value environmentExecutionContribution) EnvironmentIntents() []launch.EnvironmentIntent {
	return append([]launch.EnvironmentIntent(nil), value.intents...)
}

func environmentExecutionPlan(recipe authority.Recipe, executable, source string) authority.Plan {
	intent := launch.EnvironmentIntent{ID: "selected", Destination: "SELECTED_VALUE", Scope: environmentintent.ScopeAttachedProcessTree, SourceKind: environmentintent.SourceHostEnvironment, SourceName: source, Required: true, Classification: environmentintent.ClassificationNonSecret}
	requirements := authority.TargetRequirements{Recipe: recipe, Executable: executable}
	if recipe == authority.RecipeDevin {
		requirements.Semantics = authority.DevinSemantics()
	}
	if recipe == authority.RecipeCodex {
		requirements.Semantics = authority.CodexSemantics()
	}
	overlay := ""
	if recipe == authority.RecipeDevin || recipe == authority.RecipeCodex {
		overlay = string(recipe)
	}
	return authority.New([]authority.Contribution{{ID: "environment", Value: environmentExecutionContribution{intents: []launch.EnvironmentIntent{intent}}}}, launch.WorkspaceAccessReadOnly, 3, overlay, requirements)
}

func TestEnvironmentMissingRequiredPrecedesSessionAcrossPublicExecutors(t *testing.T) {
	for _, recipe := range []authority.Recipe{authority.RecipeShell, authority.RecipeCommand, authority.RecipeDevin} {
		t.Run(string(recipe), func(t *testing.T) {
			workspace, sessions := t.TempDir(), filepath.Join(t.TempDir(), "sessions")
			executable := executableFixture(t, workspace)
			plan := environmentExecutionPlan(authority.RecipeShell, executable, "MISSING_SOURCE")
			sandbox := &fakeSandbox{process: &fakeProcess{}}
			executor := newExecutor(sandbox)
			executor.environmentLookup = func(string) (string, bool) { return "", false }
			var err error
			switch recipe {
			case authority.RecipeShell:
				err = executor.RunShell(context.Background(), ShellRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
			case authority.RecipeCommand:
				command, resolveErr := runcommand.Resolve(workspace, []string{executable})
				if resolveErr != nil {
					t.Fatal(resolveErr)
				}
				plan, err = plan.ForCommand()
				if err == nil {
					_, err = executor.RunCommand(context.Background(), CommandRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Command: command, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
				}
			case authority.RecipeDevin:
				plan = environmentExecutionPlan(authority.RecipeDevin, executable, "MISSING_SOURCE")
				_, err = executor.RunDevin(context.Background(), DevinRequest{SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
			}
			if !errors.Is(err, ErrEnvironmentUnavailable) || sandbox.prepares != 0 || !sandbox.check.RequiresEnvironment {
				t.Fatalf("missing selected environment err=%v prepares=%d check=%+v", err, sandbox.prepares, sandbox.check)
			}
			if _, statErr := os.Stat(sessions); !os.IsNotExist(statErr) {
				t.Fatalf("missing selected environment created Session: %v", statErr)
			}
		})
	}
}

func TestEnvironmentDevinVerifyAndLaunchKeepPreflightsValueFree(t *testing.T) {
	workspace, executable := t.TempDir(), "devin"
	plan := environmentExecutionPlan(authority.RecipeDevin, executable, "PRESENT_SOURCE")
	for _, verify := range []bool{true, false} {
		t.Run(map[bool]string{true: "verify", false: "launch"}[verify], func(t *testing.T) {
			requests := []launch.ProcessRequest{}
			processes := []*fakeProcess{{write: []byte("[]\n")}, {write: []byte("Logged in\n")}}
			if !verify {
				processes = append(processes, &fakeProcess{})
			}
			sandbox := &sequenceSandbox{processes: processes, requests: &requests}
			executor := newExecutor(sandbox)
			executor.environmentLookup = func(name string) (string, bool) { return "selected", name == "PRESENT_SOURCE" }
			request := DevinRequest{SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: workspace, ResolvedPlan: &plan, ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
			if verify {
				if err := executor.VerifyDevin(context.Background(), request); err != nil {
					t.Fatal(err)
				}
			} else if code, err := executor.RunDevin(context.Background(), request); code != 0 || err != nil {
				t.Fatalf("RunDevin=(%d,%v)", code, err)
			}
			for index, processRequest := range requests {
				wantFinal := !verify && index == len(requests)-1
				if (processRequest.Environment != nil) != wantFinal {
					t.Fatalf("generation %d environment=%v wantFinal=%t", index, processRequest.Environment, wantFinal)
				}
			}
		})
	}
}

func TestEnvironmentVerifyDevinMissingRequiredPrecedesSession(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions")
	plan := environmentExecutionPlan(authority.RecipeDevin, "devin", "MISSING_SOURCE")
	requests := []launch.ProcessRequest{}
	executor := newExecutor(&sequenceSandbox{requests: &requests})
	executor.environmentLookup = func(string) (string, bool) { return "", false }
	err := executor.VerifyDevin(context.Background(), DevinRequest{SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), ResolvedPlan: &plan, ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
	if !errors.Is(err, ErrEnvironmentUnavailable) || len(requests) != 0 {
		t.Fatalf("VerifyDevin missing environment err=%v prepares=%d", err, len(requests))
	}
	if _, statErr := os.Stat(sessions); !os.IsNotExist(statErr) {
		t.Fatalf("VerifyDevin missing environment created Session: %v", statErr)
	}
}

func TestEnvironmentLeaseReleaseWaitsForRetainedCleanup(t *testing.T) {
	for _, phase := range []string{"start", "wait"} {
		t.Run(phase, func(t *testing.T) {
			done, failed := make(chan struct{}), make(chan struct{})
			targetErr := errors.New(phase + " failure")
			sandbox := &environmentLifecycleSandbox{request: make(chan launch.ProcessRequest, 1), process: &environmentLifecycleProcess{phase: phase, failure: targetErr, failed: failed, cleanup: done}}
			executor := newExecutor(sandbox)
			executor.environmentLookup = func(string) (string, bool) { return "selected", true }
			plan := environmentExecutionPlan(authority.RecipeShell, systemShell, "PRESENT_SOURCE")
			result := make(chan error, 1)
			go func() {
				result <- executor.RunShell(context.Background(), ShellRequest{SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(), ResolvedPlan: &plan, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
			}()
			request := <-sandbox.request
			<-failed
			lease := request.Environment
			if lease == nil || lease.WriteFrame(io.Discard) != nil {
				t.Fatal("lease unavailable before cleanup proof")
			}
			close(done)
			if err := <-result; !errors.Is(err, targetErr) {
				t.Fatalf("target failure precedence = %v, want %v", err, targetErr)
			}
			for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
				if errors.Is(lease.WriteFrame(io.Discard), environmentresource.ErrReleased) {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("lease was not released after CleanupDone")
		})
	}
}

type environmentLifecycleSandbox struct {
	request chan launch.ProcessRequest
	process launch.Process
}

func (*environmentLifecycleSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (*environmentLifecycleSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (sandbox *environmentLifecycleSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.request <- request
	return sandbox.process, nil
}

type environmentLifecycleProcess struct {
	phase   string
	failure error
	failed  chan struct{}
	cleanup <-chan struct{}
}

func (process *environmentLifecycleProcess) Start() error {
	if process.phase == "start" {
		close(process.failed)
		return process.failure
	}
	return nil
}
func (process *environmentLifecycleProcess) Wait() error {
	close(process.failed)
	return process.failure
}
func (*environmentLifecycleProcess) Signal(os.Signal) error               { return nil }
func (process *environmentLifecycleProcess) CleanupDone() <-chan struct{} { return process.cleanup }

type environmentCodexSandbox struct {
	requests []launch.ProcessRequest
	check    launch.SandboxCheck
	cleanup  <-chan struct{}
	prepared chan launch.ProcessRequest
}

func (*environmentCodexSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (sandbox *environmentCodexSandbox) Check(_ context.Context, check launch.SandboxCheck) error {
	sandbox.check = check
	return nil
}
func (sandbox *environmentCodexSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	index := len(sandbox.requests)
	sandbox.requests = append(sandbox.requests, request)
	if sandbox.prepared != nil {
		sandbox.prepared <- request
	}
	process := &fakeProcess{output: request.Terminal.Output}
	if index == 0 {
		process.write = []byte("codex-cli " + SupportedCodexVersion + "\n")
	} else {
		process.cleanup = sandbox.cleanup
	}
	return process, nil
}

func environmentCodexRegistry(t *testing.T, sandbox launch.ProcessSandbox) (*CodexAuthService, string, string) {
	t.Helper()
	registry, _, _, sessions := newBindingTestRegistry(t, "work", testChatGPTAuthJSON(t, "user", "workspace"))
	binary := filepath.Join(filepath.Dir(sessions), "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessions, WorkingDirectory: registry.workingDirectory}, sandbox)
	return registry, sessions, binary
}

func TestEnvironmentCodexMissingPrecedesSessionAndVersionStaysValueFree(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		sandbox := &environmentCodexSandbox{}
		registry, sessions, binary := environmentCodexRegistry(t, sandbox)
		registry.environmentLookup = func(string) (string, bool) { return "", false }
		plan := environmentExecutionPlan(authority.RecipeCodex, binary, "MISSING_SOURCE").WithAuthRef("work")
		if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}}); code != 1 || !errors.Is(err, ErrEnvironmentUnavailable) {
			t.Fatalf("missing Codex environment = (%d,%v)", code, err)
		}
		if len(sandbox.requests) != 0 || !sandbox.check.RequiresEnvironment {
			t.Fatalf("missing Codex environment reached preparation: %#v", sandbox.requests)
		}
		if _, err := os.Stat(sessions); !os.IsNotExist(err) {
			t.Fatalf("missing Codex environment created Session: %v", err)
		}
	})

	t.Run("present", func(t *testing.T) {
		done := make(chan struct{})
		sandbox := &environmentCodexSandbox{cleanup: done, prepared: make(chan launch.ProcessRequest, 2)}
		registry, _, binary := environmentCodexRegistry(t, sandbox)
		registry.environmentLookup = func(name string) (string, bool) { return "selected", name == "PRESENT_SOURCE" }
		plan := environmentExecutionPlan(authority.RecipeCodex, binary, "PRESENT_SOURCE").WithAuthRef("work")
		result := make(chan error, 1)
		go func() {
			_, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
			result <- err
		}()
		awaitPrepared := func(label string) launch.ProcessRequest {
			t.Helper()
			select {
			case request := <-sandbox.prepared:
				return request
			case err := <-result:
				t.Fatalf("Codex execution returned before %s preparation: %v", label, err)
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for %s preparation", label)
			}
			return launch.ProcessRequest{}
		}
		versionRequest, finalRequest := awaitPrepared("version"), awaitPrepared("final")
		if versionRequest.Environment != nil || finalRequest.Environment == nil {
			t.Fatalf("Codex version/final projections = (%v,%v)", versionRequest.Environment, finalRequest.Environment)
		}
		lease := finalRequest.Environment
		if err := lease.WriteFrame(io.Discard); err != nil {
			t.Fatalf("Codex lease released before cleanup: %v", err)
		}
		close(done)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
			if errors.Is(lease.WriteFrame(io.Discard), environmentresource.ErrReleased) {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("Codex lease was not released after cleanup")
	})
}

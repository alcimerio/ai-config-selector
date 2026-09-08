package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// TestRunEntrypointsEarlyPhaseMatrix keeps the two registered entrypoints
// aligned through their intentionally shared early lifecycle: Check, Session
// creation/materialization, and the first contained process preparation.
// Later Start, Wait, signal, and cleanup settlement paths have dedicated tests.
func TestRunEntrypointsEarlyPhaseMatrix(t *testing.T) {
	for _, target := range []string{"shell", "devin"} {
		for _, phase := range []string{
			"check failure", "check cancellation", "Session creation failure",
			"materialization failure", "materialization cancellation",
			"Prepare failure", "Prepare cancellation",
		} {
			t.Run(target+"/"+phase, func(t *testing.T) {
				failure := errors.New("phase matrix " + phase)
				if phase == "check cancellation" || phase == "materialization cancellation" || phase == "Prepare cancellation" {
					failure = context.Canceled
				}
				sessions := filepath.Join(t.TempDir(), "sessions")
				if phase == "Session creation failure" {
					if err := os.WriteFile(sessions, []byte("not a directory"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				sandbox := &phaseMatrixSandbox{}
				materialized := 0
				requestMaterializer := materializerFunc(func(string) error {
					materialized++
					if phase == "materialization cancellation" {
						if ctx.Err() != nil {
							t.Fatal("context canceled before materialization")
						}
						cancel()
					}
					if phase == "materialization failure" || phase == "materialization cancellation" {
						return failure
					}
					return nil
				})
				switch phase {
				case "check failure", "check cancellation":
					sandbox.checkErr = failure
					if phase == "check cancellation" {
						sandbox.cancelCheck = cancel
					}
				case "Prepare failure", "Prepare cancellation":
					sandbox.prepareErrAt, sandbox.prepareErr = 0, failure
					if phase == "Prepare cancellation" {
						sandbox.cancelPrepare = cancel
					}
				}

				code, err := runPhaseMatrixEntrypoint(t, ctx, target, sandbox, sessions, requestMaterializer)
				if target == "devin" && code != 1 {
					t.Fatalf("RunDevin exit code = %d, want 1", code)
				}
				if target == "shell" && code != 0 {
					t.Fatalf("RunShell synthetic exit code = %d, want 0", code)
				}
				if strings.Contains(phase, "cancellation") && (ctx.Err() != context.Canceled || sandbox.canceledBeforePhase) {
					t.Fatal("cancellation did not originate at the selected phase")
				}
				phaseMatrixAssertError(t, target, phase, err, failure, devinruntime.CapabilitySkillIsolation)
				phaseMatrixAssertEarlyBoundary(t, target, phase, sessions, sandbox, materialized)
			})
		}
	}
}

// TestRunDevinEarlyPhaseMatrixAtAuthentication proves a successful catalog
// probe cannot skip the fixed authentication preflight or reach interactive
// preparation when that later preflight cannot be prepared.
func TestRunDevinEarlyPhaseMatrixAtAuthentication(t *testing.T) {
	for _, phase := range []string{"Prepare failure", "Prepare cancellation"} {
		t.Run(phase, func(t *testing.T) {
			failure := errors.New("authentication " + phase)
			if phase == "Prepare cancellation" {
				failure = context.Canceled
			}
			sessions := filepath.Join(t.TempDir(), "sessions")
			sandbox := &phaseMatrixSandbox{
				processes:    []*phaseMatrixProcess{{write: []byte("[]\n")}},
				prepareErrAt: 1,
				prepareErr:   failure,
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "Prepare cancellation" {
				sandbox.cancelPrepare = cancel
			}
			code, err := runPhaseMatrixEntrypoint(t, ctx, "devin", sandbox, sessions, materializerFunc(func(string) error { return nil }))
			if code != 1 {
				t.Fatalf("RunDevin = (%d, %v), want (1, %v)", code, err, failure)
			}
			if strings.Contains(phase, "cancellation") && (ctx.Err() != context.Canceled || sandbox.canceledBeforePhase) {
				t.Fatal("cancellation did not originate at authentication preparation")
			}
			phaseMatrixAssertError(t, "devin", phase, err, failure, devinruntime.CapabilityAuthentication)
			if got, want := phaseMatrixArguments(sandbox.requests), [][]string{{"skills", "list", "--json"}, {"auth", "status"}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("fixed Devin preflight ordering = %v, want %v", got, want)
			}
			if sandbox.processes[0].starts != 1 || sandbox.processes[0].waits != 1 {
				t.Fatalf("catalog probe Start/Wait = %d/%d, want 1/1", sandbox.processes[0].starts, sandbox.processes[0].waits)
			}
			phaseMatrixAssertEmpty(t, sessions)
		})
	}
}

func TestRunDevinCarriesExecutableGrantThroughEveryGeneration(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "bin", "helper"), []byte("helper-v1"), 0o500); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(t.TempDir(), "sessions")
	contribution := authorityTestExecutableContribution{intents: []launch.ExecutableGrantIntent{{ID: "helper", ReferenceKind: launch.ExecutableReferenceWorkspaceRelative, Path: "bin/helper"}}}
	plan := authority.New([]authority.Contribution{{ID: "executables", Value: contribution}}, launch.WorkspaceAccessReadOnly, 3, "devin", authority.TargetRequirements{Recipe: authority.RecipeDevin, Executable: "devin", Semantics: authority.DevinSemantics()})
	sandbox := &phaseMatrixSandbox{}
	code, err := newExecutor(sandbox).RunDevin(context.Background(), DevinRequest{
		SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan,
		ExpectedCatalog: []skills.SkillReference{}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	})
	if err != nil || code != 0 {
		t.Fatalf("RunDevin=(%d, %v)", code, err)
	}
	if len(sandbox.check.ExecutableGrants) != 1 || len(sandbox.requests) != 3 {
		t.Fatalf("check grants=%d process generations=%d", len(sandbox.check.ExecutableGrants), len(sandbox.requests))
	}
	for index, request := range sandbox.requests {
		if len(request.ExecutableGrants) != 1 || request.ExecutableGrants[0].ID != "helper" {
			t.Fatalf("generation %d executable grants=%+v", index, request.ExecutableGrants)
		}
	}
	phaseMatrixAssertEmpty(t, sessions)
}

func runPhaseMatrixEntrypoint(t *testing.T, ctx context.Context, target string, sandbox *phaseMatrixSandbox, sessions string, materializer materializerFunc) (int, error) {
	t.Helper()
	executor := newExecutor(sandbox)
	if target == "shell" {
		return 0, executor.RunShell(ctx, ShellRequest{
			SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Materializer: materializer,
			Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
		})
	}
	return executor.RunDevin(ctx, DevinRequest{
		SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Materializer: materializer,
		Executable: "phase-matrix-devin", ExpectedCatalog: []skills.SkillReference{},
		Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard},
	})
}

func phaseMatrixAssertError(t *testing.T, target, phase string, err, failure error, capability devinruntime.Capability) {
	t.Helper()
	if phase == "Session creation failure" {
		if err == nil {
			t.Fatal("Session creation failure was suppressed")
		}
		return
	}
	if target == "devin" && (phase == "Prepare failure" || phase == "Prepare cancellation") {
		reason := devinruntime.ReasonSkillInspectionCommandFailed
		if capability == devinruntime.CapabilityAuthentication {
			reason = devinruntime.ReasonAuthenticationCommandFailed
		}
		if phase == "Prepare cancellation" {
			reason = devinruntime.ReasonVerificationInterrupted
		}
		want := devinruntime.NewPreflightError(capability, reason)
		var preflight *devinruntime.PreflightError
		if !errors.As(err, &preflight) || preflight.Category() != want.Category() || err.Error() != want.Error() {
			t.Fatalf("%s error = %v, want stable %v", phase, err, want)
		}
		return
	}
	if !errors.Is(err, failure) {
		t.Fatalf("%s error = %v, want %v", phase, err, failure)
	}
}

func phaseMatrixAssertEarlyBoundary(t *testing.T, target, phase, sessions string, sandbox *phaseMatrixSandbox, materialized int) {
	t.Helper()
	if sandbox.checks != 1 {
		t.Fatalf("Check calls = %d, want 1", sandbox.checks)
	}
	if phase == "check failure" || phase == "check cancellation" {
		if materialized != 0 || len(sandbox.requests) != 0 {
			t.Fatalf("Check failure advanced lifecycle: materialized=%d prepares=%d", materialized, len(sandbox.requests))
		}
		if _, err := os.Stat(sessions); !os.IsNotExist(err) {
			t.Fatalf("Check failure created Session state: %v", err)
		}
		return
	}
	if phase == "Session creation failure" {
		if materialized != 0 || len(sandbox.requests) != 0 {
			t.Fatalf("Session creation failure advanced lifecycle: materialized=%d prepares=%d", materialized, len(sandbox.requests))
		}
		if info, err := os.Stat(sessions); err != nil || info.IsDir() {
			t.Fatalf("Session creation failure changed its regular-file root: %v %v", info, err)
		}
		return
	}
	if materialized != 1 {
		t.Fatalf("materialization calls = %d, want 1", materialized)
	}
	if phase == "materialization failure" || phase == "materialization cancellation" {
		if len(sandbox.requests) != 0 {
			t.Fatalf("materialization failure prepared %d process(es)", len(sandbox.requests))
		}
		phaseMatrixAssertEmpty(t, sessions)
		return
	}
	if got, want := phaseMatrixArguments(sandbox.requests), phaseMatrixFirstArguments(target); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed first-process ordering = %v, want %v", got, want)
	}
	for index, process := range sandbox.processes {
		if process.starts != 0 || process.waits != 0 {
			t.Fatalf("process %d Start/Wait = %d/%d, want 0/0 after Prepare failure", index, process.starts, process.waits)
		}
	}
	phaseMatrixAssertEmpty(t, sessions)
}

func phaseMatrixFirstArguments(target string) [][]string {
	if target == "shell" {
		return [][]string{{"-f"}}
	}
	return [][]string{{"skills", "list", "--json"}}
}

func phaseMatrixArguments(requests []launch.ProcessRequest) [][]string {
	arguments := make([][]string, len(requests))
	for index, request := range requests {
		arguments[index] = request.Arguments
	}
	return arguments
}

func phaseMatrixAssertEmpty(t *testing.T, sessions string) {
	t.Helper()
	entries, err := os.ReadDir(sessions)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsettled Session state: entries=%v err=%v", entries, err)
	}
}

type phaseMatrixSandbox struct {
	canceledBeforePhase bool
	cancelCheck         context.CancelFunc
	cancelPrepare       context.CancelFunc
	checkErr            error
	prepareErr          error
	prepareErrAt        int
	checks              int
	check               launch.SandboxCheck
	requests            []launch.ProcessRequest
	processes           []*phaseMatrixProcess
}

func (*phaseMatrixSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}

func (sandbox *phaseMatrixSandbox) Check(ctx context.Context, request launch.SandboxCheck) error {
	sandbox.checks++
	sandbox.check = request
	if sandbox.cancelCheck != nil {
		if ctx.Err() != nil {
			sandbox.canceledBeforePhase = true
			return errors.New("context canceled before Check")
		}
		sandbox.cancelCheck()
		return ctx.Err()
	}
	return sandbox.checkErr
}

func (sandbox *phaseMatrixSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	index := len(sandbox.requests)
	sandbox.requests = append(sandbox.requests, request)
	if sandbox.prepareErr != nil && index == sandbox.prepareErrAt {
		if sandbox.cancelPrepare != nil {
			if ctx.Err() != nil {
				sandbox.canceledBeforePhase = true
				return nil, errors.New("context canceled before Prepare")
			}
			sandbox.cancelPrepare()
			return nil, ctx.Err()
		}
		return nil, sandbox.prepareErr
	}
	if index >= len(sandbox.processes) {
		sandbox.processes = append(sandbox.processes, &phaseMatrixProcess{})
	}
	process := sandbox.processes[index]
	process.output = request.Terminal.Output
	if len(process.write) == 0 && reflect.DeepEqual(request.Arguments, []string{"skills", "list", "--json"}) {
		process.write = []byte("[]\n")
	}
	if len(process.write) == 0 && reflect.DeepEqual(request.Arguments, []string{"auth", "status"}) {
		process.write = []byte("Logged in\n")
	}
	return process, nil
}

type phaseMatrixProcess struct {
	starts int
	waits  int
	write  []byte
	output io.Writer
}

func (process *phaseMatrixProcess) Start() error { process.starts++; return nil }
func (process *phaseMatrixProcess) Wait() error {
	process.waits++
	if len(process.write) != 0 && process.output != nil {
		_, _ = process.output.Write(process.write)
	}
	return nil
}
func (*phaseMatrixProcess) Signal(os.Signal) error       { return nil }
func (*phaseMatrixProcess) CleanupDone() <-chan struct{} { return nil }

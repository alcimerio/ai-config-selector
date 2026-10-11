package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// Neither fake runner can finish until the test has observed both in Wait.
// A serial executor therefore cannot pass this barrier.
type concurrentPreflightSandbox struct {
	entered  chan launch.ProcessRequest
	finished chan string
	release  map[string]chan struct{}
	failures map[string]error
}

func (*concurrentPreflightSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (*concurrentPreflightSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (s *concurrentPreflightSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	return &concurrentPreflightProcess{ctx: ctx, request: request, sandbox: s}, nil
}

type concurrentPreflightProcess struct {
	ctx     context.Context
	request launch.ProcessRequest
	sandbox *concurrentPreflightSandbox
}

func (*concurrentPreflightProcess) Start() error           { return nil }
func (*concurrentPreflightProcess) Signal(os.Signal) error { return nil }
func (p *concurrentPreflightProcess) Wait() error {
	name := p.request.Arguments[0]
	p.sandbox.entered <- p.request
	defer func() { p.sandbox.finished <- name }()
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case <-p.sandbox.release[name]:
	}
	if err := p.sandbox.failures[name]; err != nil {
		return err
	}
	output := "[]\n"
	if name == "auth" {
		output = "Logged in\n"
	}
	_, err := io.WriteString(p.request.Terminal.Output, output)
	return err
}

func startConcurrentPreflights(t *testing.T, failures map[string]error) (*concurrentPreflightSandbox, <-chan error, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	sandbox := &concurrentPreflightSandbox{
		entered: make(chan launch.ProcessRequest, 2), finished: make(chan string, 2),
		release:  map[string]chan struct{}{"skills": make(chan struct{}), "auth": make(chan struct{})},
		failures: failures,
	}
	created, err := session.CreateTracked(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), nil, "devin")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	joined := make(chan struct{})
	request := DevinRequest{
		WorkspaceAccess: launch.WorkspaceAccessReadOnly, Executable: "fixture-devin",
		RuntimeInputs: []string{"registered-runtime"}, RuntimeAuthority: launch.DefaultRuntimeAuthority(),
		FilesystemGrants:     []launch.FilesystemGrant{{ID: "read", Access: launch.PathAccessReadOnly}},
		FilesystemExclusions: []launch.FilesystemExclusion{{ID: "hidden"}},
		ExecutableGrants:     []launch.ExecutableGrant{{ID: "tool"}},
		sessionProtections:   []launch.SessionProtection{{Path: "/fixture/protected"}},
		selectedMCPConfig:    "/fixture/mcp.json", reserveMCPConfigNames: true,
	}
	go func() {
		defer close(joined)
		err := newExecutor(sandbox).runDevinPreflights(ctx, created, request, authority.DevinSemantics())
		if removeErr := created.Remove(); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		result <- err
	}()
	// On an assertion failure, cancel and join the executor before TempDir
	// cleanup; blocked fake runners cannot outlive their test.
	t.Cleanup(func() {
		cancel()
		<-joined
	})
	seen := make(map[string]bool)
	challenges := make(map[string]bool)
	for range 2 {
		select {
		case prepared := <-sandbox.entered:
			name := prepared.Arguments[0]
			if seen[name] {
				t.Fatalf("duplicate preflight: %s", name)
			}
			seen[name] = true
			arguments := []string{"skills", "list", "--json"}
			if name == "auth" {
				arguments = []string{"auth", "status"}
			}
			want := launch.ProcessRequest{
				Workspace: created.WorkingDirectory(), WorkspaceAccess: request.WorkspaceAccess,
				SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(),
				SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(),
				Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, Arguments: arguments,
				Terminal:         launch.Terminal{Output: prepared.Terminal.Output, ErrorOutput: io.Discard},
				RuntimeAuthority: request.RuntimeAuthority, FilesystemGrants: request.FilesystemGrants,
				FilesystemExclusions: request.FilesystemExclusions, ExecutableGrants: request.ExecutableGrants,
				SessionProtections: request.sessionProtections, SelectedMCPConfig: request.selectedMCPConfig,
				ReserveMCPConfigNames: request.reserveMCPConfigNames, RecoveryProofChallenge: prepared.RecoveryProofChallenge,
			}
			if !reflect.DeepEqual(prepared, want) || len(prepared.RecoveryProofChallenge) != launch.RecoveryProofChallengeSize {
				t.Fatalf("%s isolation differs: got %#v, want %#v", name, prepared, want)
			}
			challenge := string(prepared.RecoveryProofChallenge)
			if challenges[challenge] {
				t.Fatal("preflights reused a recovery proof challenge")
			}
			challenges[challenge] = true
		case <-ctx.Done():
			t.Fatal("both preflights did not reach the runner barrier concurrently")
		}
	}
	return sandbox, result, ctx, cancel
}

func TestDevinPreflightsRunConcurrently(t *testing.T) {
	sandbox, result, _, _ := startConcurrentPreflights(t, nil)
	close(sandbox.release["skills"])
	close(sandbox.release["auth"])
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestDevinPreflightFailuresHaveStableOrder(t *testing.T) {
	for _, test := range []struct {
		name       string
		skillsFail bool
		authFail   bool
	}{
		{name: "skills only", skillsFail: true},
		{name: "auth only", authFail: true},
		{name: "both", skillsFail: true, authFail: true},
	} {
		for _, first := range []string{"skills", "auth"} {
			t.Run(test.name+"/"+first+" finishes first", func(t *testing.T) {
				failures := make(map[string]error)
				var want []error
				if test.skillsFail {
					failures["skills"] = errors.New("PRIVATE_SKILLS_OUTPUT")
					want = append(want, devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, devinruntime.ReasonSkillInspectionCommandFailed))
				}
				if test.authFail {
					failures["auth"] = errors.New("PRIVATE_AUTH_OUTPUT")
					want = append(want, devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationCommandFailed))
				}
				sandbox, result, _, _ := startConcurrentPreflights(t, failures)
				close(sandbox.release[first])
				if got := <-sandbox.finished; got != first {
					t.Fatalf("first completion = %s, want %s", got, first)
				}
				select {
				case err := <-result:
					t.Fatalf("returned without joining sibling: %v", err)
				default:
				}
				second := "skills"
				if first == "skills" {
					second = "auth"
				}
				close(sandbox.release[second])
				err := <-result
				if err == nil || err.Error() != errors.Join(want...).Error() {
					t.Fatalf("failures = %v, want ordered %v", err, errors.Join(want...))
				}
				if len(want) == 1 {
					if _, ok := err.(*devinruntime.PreflightError); !ok {
						t.Fatalf("single failure type = %T, want original preflight error type", err)
					}
				}
				var preflight *devinruntime.PreflightError
				if !errors.As(err, &preflight) || preflight.Capability != want[0].(*devinruntime.PreflightError).Capability {
					t.Fatalf("first typed failure = %v, want %v", preflight, want[0])
				}
			})
		}
	}
}

func TestDevinPreflightsRespectCancellationAndJoinBothRunners(t *testing.T) {
	sandbox, result, _, cancel := startConcurrentPreflights(t, nil)
	cancel()
	err := <-result
	want := errors.Join(
		devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, devinruntime.ReasonVerificationInterrupted),
		devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonVerificationInterrupted),
	)
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("cancellation = %v, want %v", err, want)
	}
	if len(sandbox.finished) != 2 {
		t.Fatalf("only %d runners finished before return", len(sandbox.finished))
	}
}

func TestDevinConcurrentPreflightPreservesSandboxFailure(t *testing.T) {
	failure := &launch.SandboxError{Category: launch.SandboxProcessWaitFailed}
	sandbox, result, _, _ := startConcurrentPreflights(t, map[string]error{"auth": failure})
	close(sandbox.release["skills"])
	close(sandbox.release["auth"])
	err := <-result
	var got *launch.SandboxError
	if !errors.As(err, &got) || got != failure {
		t.Fatalf("sandbox failure = %v, want original %v", err, failure)
	}
}

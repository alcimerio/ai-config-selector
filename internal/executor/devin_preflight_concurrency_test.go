package executor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

// Neither fake runner can finish until the test has observed both in Wait.
// A serial executor therefore cannot pass this barrier.
type concurrentPreflightSandbox struct {
	entered  chan launch.ProcessRequest
	finished chan string
	release  map[string]chan struct{}
	failures map[string]error
	requests map[string]launch.ProcessRequest
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

func (p *concurrentPreflightProcess) Start() error {
	// Model the native supervisor revoking the no-target proof before start.
	return os.Remove(filepath.Join(p.request.SessionDirectory, ".acs-cleanup-proof-v1"))
}
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
		failures: failures, requests: make(map[string]launch.ProcessRequest),
	}
	materializer := materializerFunc(func(home string) error {
		return os.WriteFile(filepath.Join(home, ".config", "profile-fixture"), []byte("selected profile"), 0600)
	})
	created, err := session.CreateTracked(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), materializer, "devin")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	joined := make(chan struct{})
	host := t.TempDir()
	credential := filepath.Join(".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(host, credential)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, credential), []byte("selected credential fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	request := DevinRequest{
		WorkspaceAccess: launch.WorkspaceAccessReadOnly, Executable: "fixture-devin",
		Materializer: materializer, ExistingHomeDirectory: host,
		RuntimeInputs: []string{"registered-runtime"}, RuntimeAuthority: launch.DefaultRuntimeAuthority(),
		FilesystemGrants:     []launch.FilesystemGrant{{ID: "read", Access: launch.PathAccessReadOnly}},
		FilesystemExclusions: []launch.FilesystemExclusion{{ID: "hidden"}},
		ExecutableGrants:     []launch.ExecutableGrant{{ID: "tool"}},
	}
	request, err = projectDevinSession(created, request)
	if err != nil {
		t.Fatal(err)
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
			sandbox.requests[name] = prepared
			arguments := []string{"skills", "list", "--json"}
			if name == "auth" {
				arguments = []string{"auth", "status"}
			}
			want := launch.ProcessRequest{
				Workspace: created.WorkingDirectory(), WorkspaceAccess: request.WorkspaceAccess,
				SessionsDirectory: created.SessionsDirectory(), SessionDirectory: prepared.SessionDirectory,
				SessionHome: prepared.SessionHome, TemporaryDirectory: prepared.TemporaryDirectory,
				Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, Arguments: arguments,
				Terminal:         launch.Terminal{Output: prepared.Terminal.Output, ErrorOutput: io.Discard},
				RuntimeAuthority: request.RuntimeAuthority, FilesystemGrants: request.FilesystemGrants,
				FilesystemExclusions: request.FilesystemExclusions, ExecutableGrants: request.ExecutableGrants,
				SessionProtections: request.sessionProtections, SelectedMCPConfig: request.selectedMCPConfig,
				ReserveMCPConfigNames: request.reserveMCPConfigNames, RecoveryProofChallenge: prepared.RecoveryProofChallenge,
			}
			if name == "skills" && prepared.SessionDirectory != created.RootDirectory() {
				t.Fatal("skills left the main Session")
			}
			if name == "auth" {
				if prepared.SessionDirectory == created.RootDirectory() || filepath.Dir(prepared.SessionDirectory) != created.SessionsDirectory() {
					t.Fatal("auth must own an independent Session")
				}
				want.SessionProtections = append([]launch.SessionProtection(nil), request.sessionProtections...)
				for i := range want.SessionProtections {
					want.SessionProtections[i].Path = strings.Replace(want.SessionProtections[i].Path, created.HomeDirectory(), prepared.SessionHome, 1)
				}
			}
			if prepared.SessionHome != filepath.Join(prepared.SessionDirectory, "home") || prepared.TemporaryDirectory != filepath.Join(prepared.SessionDirectory, "tmp") {
				t.Fatal("preflight paths crossed Session boundaries")
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
	// Both processes are live: neither may have overwritten the other's
	// durable capability or published a cleanup proof for that shared root.
	capabilities := concurrentPreflightCapabilities(t, sandbox)
	store := sessionops.Store{SessionsDirectory: created.SessionsDirectory()}
	for name, prepared := range sandbox.requests {
		for relative, want := range map[string]string{filepath.Join(".config", "profile-fixture"): "selected profile", credential: "selected credential fixture"} {
			path := filepath.Join(prepared.SessionHome, relative)
			data, err := os.ReadFile(path)
			info, statErr := os.Stat(path)
			if err != nil || string(data) != want || statErr != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("%s lost selected projection %s", name, relative)
			}
		}
		for _, protection := range prepared.SessionProtections {
			if _, err := os.Stat(protection.Path); err != nil {
				t.Fatalf("%s protection missing: %v", name, err)
			}
		}
		cap := capabilities[name]
		if cap.Generation != 1 || cap.Challenge != hex.EncodeToString(prepared.RecoveryProofChallenge) {
			t.Fatalf("%s lost its live generation/challenge", name)
		}
		if _, err := os.Stat(filepath.Join(prepared.SessionDirectory, ".acs-cleanup-proof-v1")); !os.IsNotExist(err) {
			t.Fatalf("%s published cleanup proof while live: %v", name, err)
		}
		if recovered, err := store.Recover(cap.ID); err == nil || recovered.Outcome != "active" {
			t.Fatalf("%s live recovery = %+v, %v", name, recovered, err)
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
	assertConcurrentPreflightsRemoved(t, sandbox)
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
				assertConcurrentPreflightsRemoved(t, sandbox)
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
	assertConcurrentPreflightsRemoved(t, sandbox)
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

// Read private bindings by root, as public Session operations omit challenges.
type preflightCapability struct {
	ID, RootName, Challenge string
	Generation              uint64
}

func concurrentPreflightCapabilities(t *testing.T, sandbox *concurrentPreflightSandbox) map[string]preflightCapability {
	t.Helper()
	directory := filepath.Join(filepath.Dir(sandbox.requests["skills"].SessionsDirectory), "session-operations-v1", "capabilities")
	paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("live capabilities = %v, %v; want two", paths, err)
	}
	result := make(map[string]preflightCapability)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		var cap preflightCapability
		if err != nil || json.Unmarshal(data, &cap) != nil {
			t.Fatal("invalid preflight capability", err)
		}
		for name, request := range sandbox.requests {
			if cap.RootName == filepath.Base(request.SessionDirectory) {
				result[name] = cap
			}
		}
	}
	if len(result) != 2 || result["skills"].ID == result["auth"].ID {
		t.Fatal("concurrent preflights do not have independent durable bindings")
	}
	return result
}

func assertConcurrentPreflightsRemoved(t *testing.T, sandbox *concurrentPreflightSandbox) {
	t.Helper()
	store := sessionops.Store{SessionsDirectory: sandbox.requests["skills"].SessionsDirectory}
	listed, err := store.List("")
	if err != nil || len(listed.Sessions) != 2 {
		t.Fatalf("durable preflight rows = %+v, %v", listed, err)
	}
	for _, item := range listed.Sessions {
		if item.State != sessionops.StateRemoved {
			t.Fatalf("preflight not settled: %+v", item)
		}
		if recovered, err := store.Recover(item.ID); err != nil || recovered.Outcome != "removed" {
			t.Fatalf("completed recovery = %+v, %v", recovered, err)
		}
	}
	for _, request := range sandbox.requests {
		if _, err := os.Stat(request.SessionDirectory); !os.IsNotExist(err) {
			t.Fatalf("preflight root remains: %v", err)
		}
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(store.SessionsDirectory), "session-operations-v1", "capabilities", "*.json"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("settled preflight capabilities remain: %v, %v", paths, err)
	}
}

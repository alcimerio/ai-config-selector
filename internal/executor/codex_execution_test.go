package executor

import (
	"bytes"
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
)

type executionMaterializer struct{ verifyErr error }

func (executionMaterializer) Plan(context.Context, string, *launch.Plan) error { return nil }
func (executionMaterializer) Materialize(home string) error {
	return os.WriteFile(filepath.Join(home, "materialized"), []byte("yes"), 0o600)
}

func TestCodexGeneratedConfigurationConsumesTypedTargetSemantics(t *testing.T) {
	baseline := authority.CodexSemantics()
	changed := authority.CodexSemantics()
	for index := range changed.Configuration {
		if changed.Configuration[index].ID == "codex.approval" {
			changed.Configuration[index].Mode = "on-request"
		}
	}
	baselineArguments := strings.Join(codexExecutionArgumentsForSemantics(baseline, "", "/workspace"), "\n")
	changedArguments := strings.Join(codexExecutionArgumentsForSemantics(changed, "", "/workspace"), "\n")
	if baselineArguments == changedArguments || !strings.Contains(baselineArguments, `approval_policy="never"`) || !strings.Contains(changedArguments, `approval_policy="on-request"`) {
		t.Fatalf("generated arguments did not consume typed approval decision: baseline=%q changed=%q", baselineArguments, changedArguments)
	}
	baselineHome, changedHome := t.TempDir(), t.TempDir()
	if err := writeCodexExecutionConfigForSemantics(baselineHome, "", "/workspace", baseline); err != nil {
		t.Fatal(err)
	}
	if err := writeCodexExecutionConfigForSemantics(changedHome, "", "/workspace", changed); err != nil {
		t.Fatal(err)
	}
	baselineConfig, _ := os.ReadFile(filepath.Join(baselineHome, ".codex", "config.toml"))
	changedConfig, _ := os.ReadFile(filepath.Join(changedHome, ".codex", "config.toml"))
	if bytes.Equal(baselineConfig, changedConfig) || !bytes.Contains(changedConfig, []byte(`approval_policy = "on-request"`)) {
		t.Fatalf("generated file did not consume typed approval decision: baseline=%q changed=%q", baselineConfig, changedConfig)
	}
	baselinePlan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, ExecutableRequirementID: "codex", Semantics: baseline})
	changedPlan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, ExecutableRequirementID: "codex", Semantics: changed})
	if baselinePlan.AuthorityDigest() == changedPlan.AuthorityDigest() {
		t.Fatal("typed generated-configuration change did not change authority digest")
	}
	if changed.Supports(authority.RecipeCodex) {
		t.Fatal("production accepted a non-shipped target semantic variant")
	}
}

type executionSandbox struct {
	version      string
	mutate       func(string) error
	starts       []error
	waits        []error
	waitHooks    []func()
	prepareHooks []func()
	startHooks   []func()
	counts       [][2]int
	signals      [][]os.Signal
	checks       int
}

func (*executionSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (sandbox *executionSandbox) Check(context.Context, launch.SandboxCheck) error {
	sandbox.checks++
	return nil
}
func (sandbox *executionSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	index := len(sandbox.counts)
	sandbox.counts = append(sandbox.counts, [2]int{})
	sandbox.signals = append(sandbox.signals, nil)
	if index < len(sandbox.prepareHooks) && sandbox.prepareHooks[index] != nil {
		sandbox.prepareHooks[index]()
	}
	return &executionProcess{start: func() error {
		sandbox.counts[index][0]++
		if index < len(sandbox.startHooks) && sandbox.startHooks[index] != nil {
			sandbox.startHooks[index]()
		}
		if index == 0 {
			_, _ = io.WriteString(request.Terminal.Output, "codex-cli "+sandbox.version+"\n")
		} else if sandbox.mutate != nil {
			if err := sandbox.mutate(request.SessionHome); err != nil {
				return err
			}
		}
		if index < len(sandbox.starts) {
			return sandbox.starts[index]
		}
		return nil
	}, wait: func() error {
		sandbox.counts[index][1]++
		if index < len(sandbox.waitHooks) && sandbox.waitHooks[index] != nil {
			sandbox.waitHooks[index]()
		}
		if index < len(sandbox.waits) {
			return sandbox.waits[index]
		}
		return nil
	}, signal: func(received os.Signal) error {
		sandbox.signals[index] = append(sandbox.signals[index], received)
		return nil
	}}, nil
}

func TestInteractiveCodexTerminationAfterVersionCannotStartAttachedTarget(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: SupportedCodexVersion, waitHooks: []func(){func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		time.Sleep(50 * time.Millisecond)
	}}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 1 || !errors.Is(err, ErrCodexFailed) {
		t.Fatalf("canceled execution = (%d, %v)", code, err)
	}
	if len(sandbox.counts) != 1 || sandbox.counts[0] != [2]int{1, 1} {
		t.Fatalf("canceled version boundary process lifecycle = %#v", sandbox.counts)
	}
	if provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, auth) {
		t.Fatal("canceled version boundary replaced identity")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	binding, _, err := registry.resources.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatalf("canceled version boundary left identity unavailable: %v", err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestInteractiveCodexReplaysTerminationAcceptedDuringAttachedPreparation(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: SupportedCodexVersion, prepareHooks: []func(){nil, func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		time.Sleep(50 * time.Millisecond)
	}}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 0 || err != nil {
		t.Fatalf("signaled attached execution = (%d, %v)", code, err)
	}
	if len(sandbox.counts) != 2 || sandbox.counts[1] != [2]int{1, 1} {
		t.Fatalf("attached Start/Wait lifecycle = %#v", sandbox.counts)
	}
	found := false
	for _, received := range sandbox.signals[1] {
		if received == syscall.SIGTERM {
			found = true
		}
	}
	if !found {
		t.Fatalf("termination accepted during preparation was not replayed: %v", sandbox.signals[1])
	}
	if provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, auth) {
		t.Fatal("signaled attached execution replaced identity")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestInteractiveCodexResizeDuringStartCannotDisplaceTermination(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: SupportedCodexVersion, startHooks: []func(){nil, func() {
		for _, received := range []syscall.Signal{syscall.SIGWINCH, syscall.SIGTERM} {
			if err := syscall.Kill(os.Getpid(), received); err != nil {
				t.Error(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 0 || err != nil {
		t.Fatalf("signaled Start execution = (%d, %v)", code, err)
	}
	foundTermination := false
	for _, received := range sandbox.signals[1] {
		if received == syscall.SIGTERM {
			foundTermination = true
		}
	}
	if !foundTermination {
		t.Fatalf("resize displaced termination during Start: %v", sandbox.signals[1])
	}
	if sandbox.counts[1] != [2]int{1, 1} {
		t.Fatalf("signaled Start/Wait = %v", sandbox.counts[1])
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

type executionProcess struct {
	start  func() error
	wait   func() error
	signal func(os.Signal) error
}

func (process *executionProcess) Start() error { return process.start() }
func (process *executionProcess) Wait() error  { return process.wait() }
func (process *executionProcess) Signal(received os.Signal) error {
	if process.signal == nil {
		return nil
	}
	return process.signal(received)
}
func (materializer executionMaterializer) Verify(context.Context, launch.VerificationContext) error {
	return materializer.verifyErr
}

type projectedVerificationMaterializer struct{ verified *bool }

func (projectedVerificationMaterializer) Plan(context.Context, string, *launch.Plan) error {
	return nil
}

type strictCodexSkillMaterializer struct {
	observedAuth *bool
	failure      error
}

func (strictCodexSkillMaterializer) Plan(context.Context, string, *launch.Plan) error { return nil }
func (materializer strictCodexSkillMaterializer) Materialize(home string) error {
	if _, err := os.Stat(filepath.Join(home, ".codex", "auth.json")); err != nil {
		return errors.New("authentication was not projected before Skills")
	}
	if materializer.observedAuth != nil {
		*materializer.observedAuth = true
	}
	if materializer.failure != nil {
		return materializer.failure
	}
	directory := filepath.Join(home, ".codex", "skills", "shared-agents", "proof")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte("native proof"), 0o600)
}
func (strictCodexSkillMaterializer) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func TestInteractiveCodexProjectsExclusiveAuthBeforeSelectedSkills(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	observedAuth := false
	observedSkill := false
	sandbox := &executionSandbox{version: SupportedCodexVersion, prepareHooks: []func(){func() {
		entries, _ := filepath.Glob(filepath.Join(sessionsDirectory, "session-*", "home", ".codex", "skills", "shared-agents", "proof", "SKILL.md"))
		observedSkill = len(entries) == 1
	}}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New([]authority.Contribution{{ID: "strict-codex-skill", Value: strictCodexSkillMaterializer{observedAuth: &observedAuth}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 0 || err != nil {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if !observedAuth || !observedSkill || !reflect.DeepEqual(sandbox.counts, [][2]int{{1, 1}, {1, 1}}) {
		t.Fatalf("auth-before-Skills=%v projected-Skill=%v lifecycle=%v", observedAuth, observedSkill, sandbox.counts)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestInteractiveCodexMaterializationFailureCleansProjectedAuthBeforeRelease(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	observedAuth := false
	sandbox := &executionSandbox{version: SupportedCodexVersion}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New([]authority.Contribution{{ID: "failing-codex-skill", Value: strictCodexSkillMaterializer{observedAuth: &observedAuth, failure: errors.New("materialization failure")}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 1 || !errors.Is(err, ErrCodexFailed) {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if !observedAuth || len(sandbox.counts) != 0 || provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, auth) {
		t.Fatalf("auth-observed=%v processes=%d replacements=%d", observedAuth, len(sandbox.counts), provider.replaceCalls)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	if _, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("materialization failure retained marker: exists=%v err=%v", exists, err)
	}
	binding, _, err := registry.resources.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatalf("materialization failure released unusable identity: %v", err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
}
func (projectedVerificationMaterializer) Materialize(home string) error {
	return os.WriteFile(filepath.Join(home, "materialized"), []byte("yes"), 0o600)
}
func (materializer projectedVerificationMaterializer) Verify(_ context.Context, verification launch.VerificationContext) error {
	if verification.RetainProcess != nil || verification.SessionHome == "" || verification.SessionDirectory == "" || verification.TemporaryDirectory == "" || verification.WorkingDirectory == "" {
		return errors.New("verification context is incomplete or grants a process")
	}
	for _, path := range []string{
		filepath.Join(verification.SessionHome, "materialized"),
		filepath.Join(verification.SessionHome, ".codex", "auth.json"),
		filepath.Join(verification.SessionHome, ".codex", "config.toml"),
	} {
		if _, err := os.Stat(path); err != nil {
			return err
		}
	}
	*materializer.verified = true
	return errors.New("reject after observing completed projection")
}

func TestInteractiveCodexBindsOneIdentityBeforeSessionAndUsesFixedRecipe(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	var projectedConfig string
	sandbox := &fakeLoginSandbox{version: SupportedCodexVersion, prepareHook: func(request launch.ProcessRequest) {
		contents, err := os.ReadFile(filepath.Join(request.SessionHome, ".codex", "config.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projectedConfig = string(contents)
	}}
	config := codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory, PrivateRoot: filepath.Join(root, "private")}
	if err := os.MkdirAll(config.PrivateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	registry.execution = newCodexExecutionRunner(config, sandbox)
	plan := authority.New([]authority.Contribution{{ID: "test", Value: executionMaterializer{}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	exitCode, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan})
	if err != nil || exitCode != 0 {
		t.Fatalf("execution = (%d, %v)", exitCode, err)
	}
	if len(sandbox.requests) != 2 {
		t.Fatalf("prepared processes = %d, want version plus interactive", len(sandbox.requests))
	}
	for _, request := range sandbox.requests {
		if request.WorkspaceAccess != launch.WorkspaceAccessReadOnly {
			t.Fatalf("workspace access = %q", request.WorkspaceAccess)
		}
		joined := strings.Join(request.Arguments, " ")
		for _, required := range []string{`cli_auth_credentials_store="file"`, `forced_login_method="chatgpt"`, `forced_chatgpt_workspace_id="workspace"`, `model_provider="openai"`, `chatgpt_base_url="https://chatgpt.com/backend-api/"`, `sandbox_mode="danger-full-access"`, `approval_policy="never"`, `trust_level="untrusted"`, `features.plugins=false`, `features.apps=false`, `mcp_servers={}`} {
			if !strings.Contains(joined, required) {
				t.Fatalf("arguments omit %q: %#v", required, request.Arguments)
			}
		}
	}
	for _, required := range []string{`chatgpt_base_url = "https://chatgpt.com/backend-api/"`, `sandbox_mode = "danger-full-access"`, `approval_policy = "never"`, `mcp_servers = {}`, `[features]`, `plugins = false`, `apps = false`, `[projects."` + filepath.Clean(registry.workingDirectory) + `"]`, `trust_level = "untrusted"`} {
		if !strings.Contains(projectedConfig, required) {
			t.Fatalf("Session config omits %q: %s", required, projectedConfig)
		}
	}
	if got := provider.records["work"].Auth; !reflect.DeepEqual(got, auth) || provider.replaceCalls != 0 {
		t.Fatalf("unchanged target replaced identity: replacements=%d auth=%q", provider.replaceCalls, got)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestInteractiveCodexFailsBeforeExecutableAndSessionForMissingIdentity(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	if err := provider.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: "/missing/codex", SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, &fakeLoginSandbox{})
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: "/missing/codex"}).WithAuthRef("work")
	if _, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); err == nil || !strings.Contains(err.Error(), ErrIdentityNotFound.Error()) {
		t.Fatalf("missing identity error = %v", err)
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("missing identity touched Sessions: %v", err)
	}
}

func TestInteractiveCodexUsesResolvedAuthorityInsteadOfRunnerScalarInputs(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	var observedExecutableContents []string
	sandbox := &fakeLoginSandbox{version: SupportedCodexVersion, prepareHook: func(request launch.ProcessRequest) {
		contents, err := os.ReadFile(request.Executable)
		if err != nil {
			t.Fatal(err)
		}
		observedExecutableContents = append(observedExecutableContents, string(contents))
	}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: "/stale/scalar/codex", RuntimeInputs: []string{"/stale/scalar/runtime"}, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "resolved-codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "resolved-runtime")
	if err := os.WriteFile(runtime, []byte("runtime"), 0o400); err != nil {
		t.Fatal(err)
	}
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary, RuntimeInputs: []string{runtime}}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 0 || err != nil {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if len(sandbox.requests) != 2 {
		t.Fatalf("processes = %d", len(sandbox.requests))
	}
	for index, request := range sandbox.requests {
		if observedExecutableContents[index] != "target" || request.Executable == "/stale/scalar/codex" || !reflect.DeepEqual(request.RuntimeInputs, []string{runtime}) {
			t.Fatalf("process authority = executable %q runtime %#v", request.Executable, request.RuntimeInputs)
		}
	}
}

func TestInteractiveCodexRunsRegisteredVerificationBeforeAnyTargetProcess(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: SupportedCodexVersion}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	verified := false
	plan := authority.New([]authority.Contribution{{ID: "rejecting", Value: projectedVerificationMaterializer{verified: &verified}}}, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 1 || !errors.Is(err, ErrCodexFailed) {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if !verified || sandbox.checks != 1 || len(sandbox.counts) != 0 {
		t.Fatalf("verified=%v, sandbox checks=%d, prepared target processes=%d", verified, sandbox.checks, len(sandbox.counts))
	}
	if provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, auth) {
		t.Fatal("verification failure replaced identity")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	binding, _, err := registry.resources.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatalf("verification failure left identity unavailable: %v", err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestInteractiveCodexCommitsOnlySuccessfulSameIdentityRefresh(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	refreshed := []byte(strings.Replace(string(original), "2026-08-29T12:34:56Z", "2026-08-29T14:34:56Z", 1))
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: SupportedCodexVersion, mutate: func(home string) error {
		return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), refreshed, 0o600)
	}}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New(nil, launch.WorkspaceAccessReadWrite, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); err != nil || code != 0 {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if provider.replaceCalls != 1 || !reflect.DeepEqual(provider.records["work"].Auth, refreshed) {
		t.Fatalf("refresh was not committed once: replacements=%d", provider.replaceCalls)
	}
	if !reflect.DeepEqual(sandbox.counts, [][2]int{{1, 1}, {1, 1}}) {
		t.Fatalf("Start/Wait counts = %#v", sandbox.counts)
	}
}

func TestInteractiveCodexFailedRunCannotReplaceIdentityAndFailedStartIsNotWaited(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	changed := []byte(strings.Replace(string(original), "2026-08-29T12:34:56Z", "2026-08-29T14:34:56Z", 1))
	for _, test := range []struct {
		name      string
		startErr  error
		waitErr   error
		wantCount [][2]int
	}{
		{name: "failed start", startErr: errors.New("private start detail"), wantCount: [][2]int{{1, 1}, {1, 0}}},
		{name: "failed wait", waitErr: func() error { err := exec.Command("sh", "-c", "exit 7").Run(); return err }(), wantCount: [][2]int{{1, 1}, {1, 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", original)
			root := filepath.Dir(sessionsDirectory)
			binary := filepath.Join(root, "codex")
			if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
				t.Fatal(err)
			}
			sandbox := &executionSandbox{version: SupportedCodexVersion, starts: []error{nil, test.startErr}, waits: []error{nil, test.waitErr}, mutate: func(home string) error {
				return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), changed, 0o600)
			}}
			registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
			plan := authority.New(nil, launch.WorkspaceAccessReadWrite, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
			if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); err == nil || code == 0 {
				t.Fatalf("failed execution = (%d, %v)", code, err)
			}
			if provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, original) {
				t.Fatal("failed run replaced the durable identity")
			}
			if !reflect.DeepEqual(sandbox.counts, test.wantCount) {
				t.Fatalf("Start/Wait counts = %#v, want %#v", sandbox.counts, test.wantCount)
			}
		})
	}
}

func TestInteractiveCodexRejectsOverflowingVersionBeforeInteractiveProcess(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	root := filepath.Dir(sessionsDirectory)
	binary := filepath.Join(root, "codex")
	if err := os.WriteFile(binary, []byte("target"), 0o500); err != nil {
		t.Fatal(err)
	}
	sandbox := &executionSandbox{version: strings.Repeat("x", maximumVersionOutputSize+1)}
	registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: binary, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessionsDirectory, WorkingDirectory: registry.workingDirectory}, sandbox)
	plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: binary}).WithAuthRef("work")
	if code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan}); code != 1 || !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("execution = (%d, %v)", code, err)
	}
	if len(sandbox.counts) != 1 || !reflect.DeepEqual(sandbox.counts[0], [2]int{1, 1}) {
		t.Fatalf("process counts = %#v", sandbox.counts)
	}
	if provider.replaceCalls != 0 || !reflect.DeepEqual(provider.records["work"].Auth, auth) {
		t.Fatal("version failure replaced identity")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

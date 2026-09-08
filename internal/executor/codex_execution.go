package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// codexExecutionRunner owns the fixed target command, executable snapshot and
// native sandbox. It has no configurable command/provider/plugin surface.
type codexExecutionRunner struct {
	config             codexLoginConfig
	sandbox            launch.ProcessSandbox
	beforeSnapshotHook func()
}

func newCodexExecutionRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexExecutionRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexExecutionRunner{config: config, sandbox: sandbox}
}

func (runner *codexExecutionRunner) prepare(ctx context.Context, access launch.WorkspaceAccess, requirements authority.TargetRequirements, runtimeAuthority launch.RuntimeAuthority, filesystemGrants []launch.FilesystemGrant, executableGrants []launch.ExecutableGrant, pinned *pinnedExecutable) (*containedOperationPreparation, error) {
	if runner == nil {
		return nil, ErrCodexFailed
	}
	if requirements.Recipe != authority.RecipeCodex || !requirements.Semantics.Supports(authority.RecipeCodex) || requirements.Executable == "" || requirements.ExistingHomeDirectory != "" {
		return nil, ErrCodexFailed
	}
	config := runner.config
	config.BinaryPath = requirements.Executable
	config.RuntimeInputs = append([]string(nil), requirements.RuntimeInputs...)
	if runner.beforeSnapshotHook != nil {
		runner.beforeSnapshotHook()
	}
	preparation, err := prepareContainedOperationWithAccessAndGrantsUsingExecutable(ctx, config, runner.sandbox, access, filesystemGrants, executableGrants, pinned, ErrCodexFailed, runtimeAuthority)
	return preparation, err
}

const supportedChatGPTBaseURL = "https://chatgpt.com/backend-api/"

func codexExecutionArguments(chatGPTWorkspace, workingDirectory string, arguments ...string) []string {
	return codexExecutionArgumentsForSemantics(authority.CodexSemantics(), chatGPTWorkspace, workingDirectory, arguments...)
}

func codexExecutionArgumentsForSemantics(semantics authority.TargetSemantics, chatGPTWorkspace, workingDirectory string, arguments ...string) []string {
	// ACS is the sole sandbox and approval authority. Codex's fixed externally
	// sandboxed mode prevents an unsupported second Seatbelt layer and target
	// prompts without changing the resolved outer workspace access.
	authStorage, _ := semantics.ConfigurationMode("codex.auth-storage")
	if authStorage == "file-in-session" {
		authStorage = "file"
	}
	login, _ := semantics.ConfigurationMode("codex.login")
	provider, _ := semantics.ConfigurationMode("codex.provider")
	endpoint, _ := semantics.ConfigurationMode("codex.endpoint")
	if endpoint == "chatgpt-backend-api" {
		endpoint = supportedChatGPTBaseURL
	}
	sandboxMode, _ := semantics.ConfigurationMode("codex.sandbox")
	if sandboxMode == "danger-full-access-under-acs" {
		sandboxMode = "danger-full-access"
	}
	approval, _ := semantics.ConfigurationMode("codex.approval")
	trust, _ := semantics.ConfigurationMode("codex.project-trust")
	plugins, _ := semantics.ConfigurationMode("codex.plugins")
	apps, _ := semantics.ConfigurationMode("codex.apps")
	mcp, _ := semantics.ConfigurationMode("codex.mcp")
	overrides := []string{"-c", `cli_auth_credentials_store=` + strconv.Quote(authStorage), "-c", `forced_login_method=` + strconv.Quote(login)}
	if chatGPTWorkspace != "" {
		overrides = append(overrides, "-c", `forced_chatgpt_workspace_id=`+strconv.Quote(chatGPTWorkspace))
	}
	overrides = append(overrides,
		"-c", `model_provider=`+strconv.Quote(provider),
		"-c", `chatgpt_base_url=`+strconv.Quote(endpoint),
		"-c", `sandbox_mode=`+strconv.Quote(sandboxMode),
		"-c", `approval_policy=`+strconv.Quote(approval),
		"-c", `projects.`+strconv.Quote(filepath.Clean(workingDirectory))+`.trust_level=`+strconv.Quote(trust),
		"-c", `features.plugins=`+disabledBoolean(plugins),
		"-c", `features.apps=`+disabledBoolean(apps),
		"-c", `mcp_servers=`+disabledMap(mcp),
	)
	return append(overrides, arguments...)
}

func writeCodexExecutionConfig(home, chatGPTWorkspace, workingDirectory string) error {
	return writeCodexExecutionConfigForSemantics(home, chatGPTWorkspace, workingDirectory, authority.CodexSemantics())
}

func writeCodexExecutionConfigForSemantics(home, chatGPTWorkspace, workingDirectory string, semantics authority.TargetSemantics) error {
	codexHome := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return err
	}
	provider, _ := semantics.ConfigurationMode("codex.provider")
	authStorage, _ := semantics.ConfigurationMode("codex.auth-storage")
	if authStorage == "file-in-session" {
		authStorage = "file"
	}
	login, _ := semantics.ConfigurationMode("codex.login")
	endpoint, _ := semantics.ConfigurationMode("codex.endpoint")
	if endpoint == "chatgpt-backend-api" {
		endpoint = supportedChatGPTBaseURL
	}
	sandboxMode, _ := semantics.ConfigurationMode("codex.sandbox")
	if sandboxMode == "danger-full-access-under-acs" {
		sandboxMode = "danger-full-access"
	}
	approval, _ := semantics.ConfigurationMode("codex.approval")
	trust, _ := semantics.ConfigurationMode("codex.project-trust")
	plugins, _ := semantics.ConfigurationMode("codex.plugins")
	apps, _ := semantics.ConfigurationMode("codex.apps")
	mcp, _ := semantics.ConfigurationMode("codex.mcp")
	configuration := "cli_auth_credentials_store = " + strconv.Quote(authStorage) + "\nforced_login_method = " + strconv.Quote(login) + "\nmodel_provider = " + strconv.Quote(provider) + "\nchatgpt_base_url = " + strconv.Quote(endpoint) + "\nsandbox_mode = " + strconv.Quote(sandboxMode) + "\napproval_policy = " + strconv.Quote(approval) + "\nmcp_servers = " + disabledMap(mcp) + "\n[features]\nplugins = " + disabledBoolean(plugins) + "\napps = " + disabledBoolean(apps) + "\n[projects." + strconv.Quote(filepath.Clean(workingDirectory)) + "]\ntrust_level = " + strconv.Quote(trust) + "\n"
	if chatGPTWorkspace != "" {
		configuration = "forced_chatgpt_workspace_id = " + strconv.Quote(chatGPTWorkspace) + "\n" + configuration
	}
	return os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(configuration), 0o600)
}

func disabledBoolean(mode string) string {
	if mode == "disabled" {
		return "false"
	}
	return "true"
}
func disabledMap(mode string) string {
	if mode == "disabled" {
		return "{}"
	}
	return "{unsupported=true}"
}

func (runner *codexExecutionRunner) run(ctx context.Context, config codexLoginConfig, created *session.Session, metadata IdentityMetadata, access launch.WorkspaceAccess, challenge string, binding loginResourceBinding, arguments []string, terminal launch.Terminal, supervisor *devinSignalSupervisor, semantics authority.TargetSemantics, runtimeAuthority launch.RuntimeAuthority, filesystemGrants []launch.FilesystemGrant, executableGrants []launch.ExecutableGrant) containedRunResult {
	mode := retainedProbe
	reserved := false
	if supervisor != nil {
		if err := supervisor.reserveInteractive(); err != nil {
			return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
		}
		reserved = true
	}
	cancelReservation := func() {
		if reserved {
			supervisor.cancelInteractiveReservation()
		}
	}
	challenge, err := advanceProcessChallenge(ctx, binding, challenge)
	if err != nil {
		cancelReservation()
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	proof, err := decodeRecoveryChallenge(challenge)
	if err != nil {
		cancelReservation()
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	if _, err := created.ArmOperation(proof); err != nil {
		cancelReservation()
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	if err := binding.MarkCleanupPending(ctx); err != nil {
		cancelReservation()
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	executor := &Executor{sandbox: runner.sandbox}
	process, err := executor.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), WorkspaceAccess: access, SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(),
		Executable: config.BinaryPath, RuntimeInputs: config.RuntimeInputs, RuntimeProbePaths: config.RuntimeProbePaths,
		RecoveryProofChallenge: proof, Arguments: codexExecutionArgumentsForSemantics(semantics, metadata.Workspace, created.WorkingDirectory(), arguments...), Terminal: terminal, RuntimeAuthority: runtimeAuthority,
		FilesystemGrants: filesystemGrants,
		ExecutableGrants: executableGrants,
	})
	if err != nil {
		cancelReservation()
		if errors.Is(err, errRetainPreparedProcess) || errors.Is(err, errInvalidPreparedProcess) {
			return containedRunResult{err: ErrCodexCleanupUncertain, cleanupProven: false, cleanupChallenge: challenge}
		}
		return containedRunResult{err: err, cleanupProven: true}
	}
	if reserved {
		mode = retainedDevinReserved
	}
	runErr, cleanupErr := settleRetainedProcess(process, mode, supervisor)
	if cleanupErr != nil {
		return containedRunResult{err: ErrCodexCleanupUncertain, cleanupProven: false, cleanupProcess: process, cleanupChallenge: challenge}
	}
	return containedRunResult{err: runErr, cleanupProven: true}
}

func decodeRecoveryChallenge(value string) ([]byte, error) {
	challenge, err := hex.DecodeString(value)
	if err != nil || len(challenge) != launch.RecoveryProofChallengeSize {
		return nil, ErrCodexFailed
	}
	return challenge, nil
}

// ExecuteCodex acquires exactly one named identity before any executable or
// Session work, and retains that binding until projection removal is proven.
func (service *CodexAuthService) ExecuteCodex(ctx context.Context, request CodexRequest) (exitCode int, resultErr error) {
	if service == nil || service.execution == nil || request.ResolvedPlan == nil || request.ResolvedPlan.Requirements().Recipe != authority.RecipeCodex {
		return 1, ErrCodexFailed
	}
	preflightContext, cancelPreflight := context.WithCancel(ctx)
	defer cancelPreflight()
	supervisor := newDevinSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	requirements := request.ResolvedPlan.Requirements()
	filesystemGrants, err := request.ResolvedPlan.ResolveFilesystemGrantsForPreflight(service.workingDirectory, service.sessionsDirectory)
	if err != nil {
		return 1, ErrCodexFailed
	}
	executableGrants, err := request.ResolvedPlan.ResolveExecutableGrants(service.workingDirectory, service.sessionsDirectory)
	if err != nil {
		return 1, ErrCodexFailed
	}
	authRef, err := ParseCredentialRef(request.ResolvedPlan.AuthRef())
	if err != nil {
		return 1, err
	}
	binding, metadata, err := service.resources.AcquireStatus(preflightContext, string(authRef))
	if err != nil {
		if preflightContext.Err() != nil {
			return 1, ErrCodexFailed
		}
		return 1, err
	}
	defer func() {
		if releaseErr := binding.Release(); releaseErr != nil && !errors.Is(resultErr, ErrCodexCleanupUncertain) && !errors.Is(resultErr, ErrBindingQuarantined) {
			resultErr, exitCode = ErrBindingQuarantined, 1
		}
	}()
	var operationExecutable *pinnedExecutable
	if hasWritableFilesystemGrant(filesystemGrants) {
		operationExecutable = newPinnedExecutable(requirements.Executable)
		resolvedExecutable, resolveErr := operationExecutable.Resolve()
		if resolveErr != nil {
			return 1, ErrUnsupportedVersion
		}
		requirements.Executable = resolvedExecutable
		filesystemGrants, err = request.ResolvedPlan.ResolveFilesystemGrantsForExecutable(service.workingDirectory, service.sessionsDirectory, resolvedExecutable)
		if err != nil {
			return 1, ErrCodexFailed
		}
	}
	access := request.ResolvedPlan.WorkspaceAccess()
	runtimeAuthority := request.ResolvedPlan.RuntimeAuthority()
	preparation, err := service.execution.prepare(preflightContext, access, requirements, runtimeAuthority, filesystemGrants, executableGrants, operationExecutable)
	if err != nil {
		if preflightContext.Err() != nil {
			return 1, ErrCodexFailed
		}
		return 1, sanitizeCodexExecutionError(err)
	}
	defer preparation.Close()
	if preflightContext.Err() != nil {
		return 1, ErrCodexFailed
	}
	// The lower authentication resource owns exclusive creation of .codex.
	// Create and protect an otherwise empty Session first; common/target
	// materialization follows the exact identity projection below.
	created, challenge, err := service.createResourceBindingForTarget(ctx, binding, authRef, nil, ErrCodexFailed, "codex")
	if err != nil {
		return 1, sanitizeCodexExecutionError(err)
	}
	remove := func() error {
		if err := created.Remove(); err != nil {
			_ = created.PreserveForRecovery()
			return ErrBindingQuarantined
		}
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return ErrBindingQuarantined
		}
		return nil
	}
	if preflightContext.Err() != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	if err := binding.Project(created.HomeDirectory()); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrProjectedAuthInvalid
	}
	if err := request.ResolvedPlan.Materialize(created.HomeDirectory()); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	if err := writeCodexExecutionConfigForSemantics(created.HomeDirectory(), metadata.Workspace, created.WorkingDirectory(), requirements.Semantics); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	if preflightContext.Err() != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	// Verification observes the completed common/target/auth projection. It has
	// no process-retention capability: actual target discovery belongs to the
	// fixed native acceptance path, not arbitrary contribution subprocesses.
	if err := request.ResolvedPlan.Verify(preflightContext, launch.VerificationContext{
		SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(),
		SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), WorkingDirectory: created.WorkingDirectory(),
	}); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	version := service.execution.run(preflightContext, preparation.config, created, metadata, access, challenge, binding, []string{"--version"}, launch.Terminal{Output: &versionOutput, ErrorOutput: io.Discard}, nil, requirements.Semantics, runtimeAuthority, filesystemGrants, executableGrants)
	if preflightContext.Err() != nil && version.cleanupProven {
		version.err = ErrCodexFailed
	} else if version.err == nil && (versionOutput.overflow || strings.TrimSpace(versionOutput.String()) != "codex-cli "+service.execution.config.SupportedVersion) {
		version.err = ErrUnsupportedVersion
	}
	run := version
	if version.err == nil && version.cleanupProven && preflightContext.Err() == nil {
		run = service.execution.run(preflightContext, preparation.config, created, metadata, access, challenge, binding, nil, request.Terminal, supervisor, requirements.Semantics, runtimeAuthority, filesystemGrants, executableGrants)
	} else if version.err == nil && preflightContext.Err() != nil {
		run.err = ErrCodexFailed
	}
	if !run.cleanupProven {
		service.transferResourcePendingBinding(created, binding, cleanupChallenge(run, challenge), run.cleanupProcess)
		return 1, ErrCodexCleanupUncertain
	}
	if run.err == nil {
		if err := binding.MarkRefreshAllowed(ctx); err != nil {
			_ = created.PreserveForRecovery()
			return 1, ErrBindingQuarantined
		}
	}
	if err := binding.MarkRecoverable(ctx); err != nil {
		_ = created.PreserveForRecovery()
		return 1, ErrBindingQuarantined
	}
	if run.err != nil {
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return codexExitResult(ctx, run.err)
	}
	if _, err := binding.FinalizeStatus(ctx, created.RootDirectory()); err != nil {
		if errors.Is(err, codexauthresource.ErrProjectedAuthInvalid) {
			if cleanupErr := remove(); cleanupErr != nil {
				return 1, cleanupErr
			}
			return 1, ErrProjectedAuthInvalid
		}
		_ = created.PreserveForRecovery()
		return 1, ErrBindingQuarantined
	}
	if err := remove(); err != nil {
		return 1, err
	}
	return 0, nil
}

func codexExitResult(ctx context.Context, err error) (int, error) {
	if ctx.Err() != nil {
		return 1, ErrCodexFailed
	}
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return 1, sandboxFailure
	}
	var targetExit *exec.ExitError
	if errors.As(err, &targetExit) {
		if status, ok := targetExit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code := 128 + int(status.Signal())
			return code, &CodexExitError{Code: code}
		}
		if code := targetExit.ExitCode(); code >= 0 {
			return code, &CodexExitError{Code: code}
		}
	}
	return 1, sanitizeCodexExecutionError(err)
}

func sanitizeCodexExecutionError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	for _, safe := range []error{ErrInvalidCredentialRef, ErrIdentityNotFound, ErrIdentityBusy, ErrUnsupportedVersion, ErrProjectedAuthInvalid, ErrBindingQuarantined, ErrCodexCleanupUncertain} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrCodexFailed
}

type CodexExitError struct{ Code int }

func (err *CodexExitError) Error() string { return "Codex exited" }
func (err *CodexExitError) ExitCode() int { return err.Code }

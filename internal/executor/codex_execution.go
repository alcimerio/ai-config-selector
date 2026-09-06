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
	config  codexLoginConfig
	sandbox launch.ProcessSandbox
}

func newCodexExecutionRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexExecutionRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexExecutionRunner{config: config, sandbox: sandbox}
}

func (runner *codexExecutionRunner) prepare(ctx context.Context, access launch.WorkspaceAccess) (*containedOperationPreparation, error) {
	if runner == nil {
		return nil, ErrCodexFailed
	}
	return prepareContainedOperationWithAccess(ctx, runner.config, runner.sandbox, access, ErrCodexFailed)
}

func codexExecutionArguments(workspace string, access launch.WorkspaceAccess, arguments ...string) []string {
	mode := "read-only"
	if access == launch.WorkspaceAccessReadWrite || access == launch.WorkspaceAccessLegacy {
		mode = "workspace-write"
	}
	overrides := codexAuthRuntimeArguments(workspace)
	overrides = append(overrides,
		"-c", `model_provider="openai"`,
		"-c", `sandbox_mode=`+strconv.Quote(mode),
		"-c", `approval_policy="on-request"`,
	)
	return append(overrides, arguments...)
}

func writeCodexExecutionConfig(home, workspace string, access launch.WorkspaceAccess) error {
	codexHome := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return err
	}
	mode := "read-only"
	if access == launch.WorkspaceAccessReadWrite || access == launch.WorkspaceAccessLegacy {
		mode = "workspace-write"
	}
	configuration := "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\nmodel_provider = \"openai\"\nsandbox_mode = " + strconv.Quote(mode) + "\napproval_policy = \"on-request\"\n"
	if workspace != "" {
		configuration += "forced_chatgpt_workspace_id = " + strconv.Quote(workspace) + "\n"
	}
	return os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(configuration), 0o600)
}

func (runner *codexExecutionRunner) run(ctx context.Context, config codexLoginConfig, created *session.Session, metadata IdentityMetadata, access launch.WorkspaceAccess, challenge string, binding loginResourceBinding, arguments []string, terminal launch.Terminal) containedRunResult {
	proof, err := decodeRecoveryChallenge(challenge)
	if err != nil {
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	if err := launch.PrepareSessionCleanupProof(created.RootDirectory(), proof); err != nil {
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	if err := binding.MarkCleanupPending(ctx); err != nil {
		return containedRunResult{err: ErrCodexFailed, cleanupProven: true}
	}
	executor := &Executor{sandbox: runner.sandbox}
	process, err := executor.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), WorkspaceAccess: access, SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(),
		Executable: config.BinaryPath, RuntimeInputs: config.RuntimeInputs, RuntimeProbePaths: config.RuntimeProbePaths,
		RecoveryProofChallenge: proof, Arguments: codexExecutionArguments(metadata.Workspace, access, arguments...), Terminal: terminal,
	})
	if err != nil {
		if errors.Is(err, errRetainPreparedProcess) || errors.Is(err, errInvalidPreparedProcess) {
			return containedRunResult{err: ErrCodexCleanupUncertain, cleanupProven: false}
		}
		return containedRunResult{err: err, cleanupProven: true}
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedAttached, nil)
	if cleanupErr != nil {
		return containedRunResult{err: ErrCodexCleanupUncertain, cleanupProven: false, cleanupProcess: process}
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
	authRef, err := ParseCredentialRef(request.ResolvedPlan.AuthRef())
	if err != nil {
		return 1, err
	}
	binding, metadata, err := service.resources.AcquireStatus(ctx, string(authRef))
	if err != nil {
		return 1, err
	}
	defer func() {
		if releaseErr := binding.Release(); releaseErr != nil && !errors.Is(resultErr, ErrCodexCleanupUncertain) && !errors.Is(resultErr, ErrBindingQuarantined) {
			resultErr, exitCode = ErrBindingQuarantined, 1
		}
	}()
	access := request.ResolvedPlan.WorkspaceAccess()
	preparation, err := service.execution.prepare(ctx, access)
	if err != nil {
		return 1, sanitizeCodexExecutionError(err)
	}
	defer preparation.Close()
	created, challenge, err := service.createResourceBinding(ctx, binding, authRef, *request.ResolvedPlan, ErrCodexFailed)
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
	if err := binding.Project(created.HomeDirectory()); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrProjectedAuthInvalid
	}
	if err := writeCodexExecutionConfig(created.HomeDirectory(), metadata.Workspace, access); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return 1, cleanupErr
		}
		return 1, ErrCodexFailed
	}
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	version := service.execution.run(ctx, preparation.config, created, metadata, access, challenge, binding, []string{"--version"}, launch.Terminal{Output: &versionOutput, ErrorOutput: io.Discard})
	if version.err == nil && !versionOutput.overflow && strings.TrimSpace(versionOutput.String()) != "codex-cli "+service.execution.config.SupportedVersion {
		version.err = ErrUnsupportedVersion
	}
	run := version
	if version.err == nil && version.cleanupProven {
		run = service.execution.run(ctx, preparation.config, created, metadata, access, challenge, binding, nil, request.Terminal)
	}
	if !run.cleanupProven {
		service.transferResourcePendingBinding(created, binding, challenge, run.cleanupProcess)
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

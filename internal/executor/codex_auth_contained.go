package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type containedRunResult struct {
	err            error
	cleanupProven  bool
	cleanupProcess launch.Process
}

type containedOperationPreparation struct {
	config    codexLoginConfig
	cleanup   func()
	closeOnce sync.Once
}

func prepareContainedOperation(
	ctx context.Context,
	config codexLoginConfig,
	sandbox launch.ProcessSandbox,
	operationFailure error,
) (*containedOperationPreparation, error) {
	return prepareContainedOperationWithAccess(ctx, config, sandbox, launch.WorkspaceAccessLegacy, operationFailure)
}

func prepareContainedOperationWithAccess(
	ctx context.Context,
	config codexLoginConfig,
	sandbox launch.ProcessSandbox,
	workspaceAccess launch.WorkspaceAccess,
	operationFailure error,
) (*containedOperationPreparation, error) {
	if sandbox == nil {
		return nil, operationFailure
	}
	if err := validateContainedAuthWorkspace(config); err != nil {
		return nil, operationFailure
	}
	root, err := executableSnapshotRoot(config)
	if err != nil {
		return nil, ErrUnsupportedVersion
	}
	pinned := newPinnedExecutable(config.BinaryPath)
	executable, cleanup, err := pinned.Snapshot(root)
	if err != nil {
		return nil, ErrUnsupportedVersion
	}
	preparedConfig := config
	preparedConfig.BinaryPath = executable
	preparation := &containedOperationPreparation{config: preparedConfig, cleanup: cleanup}
	if err := sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: config.WorkingDirectory, WorkspaceAccess: workspaceAccess, SessionsDirectory: config.SessionsDirectory,
		Executable: executable, RuntimeInputs: config.RuntimeInputs,
		RuntimeProbePaths: config.RuntimeProbePaths,
	}); err != nil {
		preparation.Close()
		return nil, err
	}
	return preparation, nil
}

func (preparation *containedOperationPreparation) Close() {
	if preparation == nil {
		return
	}
	preparation.closeOnce.Do(func() {
		if preparation.cleanup != nil {
			preparation.cleanup()
		}
	})
}

// runContainedCodex owns the prepare-retain-run-settle invariant shared by
// login and status while allowing each operation to select its stable error.
func runContainedCodex(
	ctx context.Context,
	config codexLoginConfig,
	sandbox launch.ProcessSandbox,
	created *session.Session,
	workspace string,
	proofChallenge string,
	binding loginResourceBinding,
	arguments []string,
	terminal launch.Terminal,
	targetFailure error,
	cleanupFailure error,
) containedRunResult {
	challenge, err := hex.DecodeString(proofChallenge)
	if err != nil || len(challenge) != launch.RecoveryProofChallengeSize {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	if err := launch.PrepareSessionCleanupProof(created.RootDirectory(), challenge); err != nil {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	if binding == nil {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	if err := binding.MarkCleanupPending(ctx); err != nil {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	executor := &Executor{sandbox: sandbox}
	process, err := executor.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: config.BinaryPath,
		RuntimeInputs: config.RuntimeInputs, RuntimeProbePaths: config.RuntimeProbePaths,
		RecoveryProofChallenge: challenge,
		Arguments:              codexAuthRuntimeArguments(workspace, arguments...), Terminal: terminal,
	})
	if err != nil {
		if errors.Is(err, errRetainPreparedProcess) || errors.Is(err, errInvalidPreparedProcess) {
			// Process preparation already succeeded after the durable marker was
			// armed. Without a valid retained handle, process-tree cleanup cannot
			// be proven, so preserve the protected Session for recovery.
			return containedRunResult{err: cleanupFailure, cleanupProven: false}
		}
		return containedRunResult{err: err, cleanupProven: true}
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedAttached, nil)
	if cleanupErr != nil {
		return containedRunResult{
			err: cleanupFailure, cleanupProven: false, cleanupProcess: process,
		}
	}
	if runErr != nil {
		var sandboxFailure *launch.SandboxError
		if errors.As(runErr, &sandboxFailure) {
			return containedRunResult{err: sandboxFailure, cleanupProven: true}
		}
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	return containedRunResult{cleanupProven: true}
}

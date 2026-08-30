package codexauth

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type containedRunResult struct {
	err            error
	cleanupProven  bool
	cleanupProcess launch.Process
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
	arguments []string,
	terminal launch.Terminal,
	targetFailure error,
	cleanupFailure error,
) containedRunResult {
	challenge, err := hex.DecodeString(proofChallenge)
	if err != nil || len(challenge) != launch.RecoveryProofChallengeSize {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	if err := launch.PrepareSessionCleanupProof(created.RootDirectory()); err != nil {
		return containedRunResult{err: targetFailure, cleanupProven: true}
	}
	process, err := sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: config.BinaryPath,
		RuntimeInputs: config.RuntimeInputs, RuntimeProbePaths: config.RuntimeProbePaths,
		RecoveryProofChallenge: challenge,
		Arguments:              codexAuthRuntimeArguments(workspace, arguments...), Terminal: terminal,
	})
	if err != nil {
		return containedRunResult{err: err, cleanupProven: true}
	}
	process, err = created.RetainUntilProcessDone(process)
	if err != nil {
		return containedRunResult{err: cleanupFailure, cleanupProven: false}
	}
	runErr := launch.RunAttached(process)
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
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

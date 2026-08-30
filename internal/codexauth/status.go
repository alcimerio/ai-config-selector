package codexauth

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type statusRunResult struct {
	err            error
	cleanupProven  bool
	cleanupProcess launch.Process
}

type statusRunner interface {
	Check(context.Context) error
	Run(context.Context, *session.Session, string) statusRunResult
}

type codexStatusRunner struct {
	config  codexLoginConfig
	sandbox launch.ProcessSandbox
}

func newCodexStatusRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexStatusRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexStatusRunner{config: config, sandbox: sandbox}
}

func (runner *codexStatusRunner) Check(ctx context.Context) error {
	if runner == nil || runner.sandbox == nil {
		return ErrStatusFailed
	}
	return runner.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: runner.config.WorkingDirectory, SessionsDirectory: runner.config.SessionsDirectory,
		Executable: runner.config.BinaryPath, RuntimeInputs: runner.config.RuntimeInputs,
		RuntimeProbePaths: runner.config.RuntimeProbePaths,
	})
}

func (runner *codexStatusRunner) Run(ctx context.Context, created *session.Session, workspace string) statusRunResult {
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	result := runner.run(ctx, created, workspace, []string{"--version"}, launch.Terminal{
		Output: &versionOutput, ErrorOutput: io.Discard,
	})
	if result.err != nil || !result.cleanupProven {
		return result
	}
	if versionOutput.overflow || strings.TrimSpace(versionOutput.String()) != "codex-cli "+runner.config.SupportedVersion {
		return statusRunResult{err: ErrUnsupportedVersion, cleanupProven: true}
	}
	return runner.run(ctx, created, workspace, []string{"login", "status"}, launch.Terminal{
		Output: io.Discard, ErrorOutput: io.Discard,
	})
}

func (runner *codexStatusRunner) run(
	ctx context.Context,
	created *session.Session,
	workspace string,
	arguments []string,
	terminal launch.Terminal,
) statusRunResult {
	process, err := runner.sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: runner.config.BinaryPath,
		RuntimeInputs: runner.config.RuntimeInputs, RuntimeProbePaths: runner.config.RuntimeProbePaths,
		Arguments: codexAuthRuntimeArguments(workspace, arguments...), Terminal: terminal,
	})
	if err != nil {
		return statusRunResult{err: err, cleanupProven: true}
	}
	process, err = created.RetainUntilProcessDone(process)
	if err != nil {
		return statusRunResult{err: ErrBindingQuarantined, cleanupProven: false}
	}
	runErr := launch.RunAttached(process)
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
		return statusRunResult{err: ErrBindingQuarantined, cleanupProven: false, cleanupProcess: process}
	}
	if runErr != nil {
		var sandboxFailure *launch.SandboxError
		if errors.As(runErr, &sandboxFailure) {
			return statusRunResult{err: sandboxFailure, cleanupProven: true}
		}
		return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
	}
	return statusRunResult{cleanupProven: true}
}

func sanitizeStatusError(err error) error {
	if err == nil {
		return nil
	}
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	for _, safe := range []error{ErrUnsupportedVersion, ErrStatusFailed, ErrBindingQuarantined} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrStatusFailed
}

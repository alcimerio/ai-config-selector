package codexauth

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type statusRunResult = containedRunResult

type statusRunner interface {
	Check(context.Context) error
	Run(context.Context, *session.Session, string) statusRunResult
}

type codexStatusRunner struct {
	config     codexLoginConfig
	executable *pinnedExecutable
	sandbox    launch.ProcessSandbox
}

func newCodexStatusRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexStatusRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexStatusRunner{
		config: config, executable: newPinnedExecutable(config.BinaryPath), sandbox: sandbox,
	}
}

func (runner *codexStatusRunner) Check(ctx context.Context) error {
	if runner == nil || runner.sandbox == nil {
		return ErrStatusFailed
	}
	executable, err := runner.executable.Resolve()
	if err != nil {
		return ErrUnsupportedVersion
	}
	return runner.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: runner.config.WorkingDirectory, SessionsDirectory: runner.config.SessionsDirectory,
		Executable: executable, RuntimeInputs: runner.config.RuntimeInputs,
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
	executable, err := runner.executable.Resolve()
	if err != nil {
		return containedRunResult{err: ErrUnsupportedVersion, cleanupProven: true}
	}
	config := runner.config
	config.BinaryPath = executable
	return runContainedCodex(
		ctx, config, runner.sandbox, created, workspace, arguments, terminal,
		ErrStatusFailed, ErrBindingQuarantined,
	)
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

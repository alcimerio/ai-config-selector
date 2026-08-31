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

type statusPreparation struct {
	run       func(context.Context, *session.Session, string, string, func() error) statusRunResult
	operation *containedOperationPreparation
}

func (preparation statusPreparation) Run(
	ctx context.Context,
	created *session.Session,
	workspace string,
	proofChallenge string,
	beginProcess func() error,
) statusRunResult {
	if preparation.run == nil {
		return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
	}
	return preparation.run(ctx, created, workspace, proofChallenge, beginProcess)
}

func (preparation statusPreparation) Close() {
	preparation.operation.Close()
}

type statusRunner interface {
	Prepare(context.Context) (statusPreparation, error)
}

type codexStatusRunner struct {
	config  codexLoginConfig
	sandbox launch.ProcessSandbox
}

func newCodexStatusRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexStatusRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexStatusRunner{
		config: config, sandbox: sandbox,
	}
}

func (runner *codexStatusRunner) Prepare(ctx context.Context) (statusPreparation, error) {
	if runner == nil {
		return statusPreparation{}, ErrStatusFailed
	}
	operation, err := prepareContainedOperation(ctx, runner.config, runner.sandbox, ErrStatusFailed)
	if err != nil {
		return statusPreparation{}, err
	}
	return statusPreparation{
		run: func(
			ctx context.Context,
			created *session.Session,
			workspace string,
			proofChallenge string,
			beginProcess func() error,
		) statusRunResult {
			return runner.runOperation(ctx, operation.config, created, workspace, proofChallenge, beginProcess)
		},
		operation: operation,
	}, nil
}

func (runner *codexStatusRunner) runOperation(
	ctx context.Context,
	config codexLoginConfig,
	created *session.Session,
	workspace string,
	proofChallenge string,
	beginProcess func() error,
) statusRunResult {
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	result := runner.run(ctx, config, created, workspace, proofChallenge, beginProcess, []string{"--version"}, launch.Terminal{
		Output: &versionOutput, ErrorOutput: io.Discard,
	})
	if result.err != nil || !result.cleanupProven {
		return result
	}
	if versionOutput.overflow || strings.TrimSpace(versionOutput.String()) != "codex-cli "+runner.config.SupportedVersion {
		return statusRunResult{err: ErrUnsupportedVersion, cleanupProven: true}
	}
	return runner.run(ctx, config, created, workspace, proofChallenge, beginProcess, []string{"login", "status"}, launch.Terminal{
		Output: io.Discard, ErrorOutput: io.Discard,
	})
}

func (runner *codexStatusRunner) run(
	ctx context.Context,
	config codexLoginConfig,
	created *session.Session,
	workspace string,
	proofChallenge string,
	beginProcess func() error,
	arguments []string,
	terminal launch.Terminal,
) statusRunResult {
	return runContainedCodex(
		ctx, config, runner.sandbox, created, workspace, proofChallenge, beginProcess, arguments, terminal,
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

package devin

import (
	"context"
	"errors"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// Launch delegates the complete protected Devin lifecycle to executor. The
// adapter supplies only validated configuration and selected profile data.
func (a *Adapter) Launch(ctx context.Context, sessionsDirectory, workingDirectory string, resolved category.ResolvedProfile, terminal launch.Terminal) (int, error) {
	exitCode, err := a.executor.RunDevin(ctx, executor.DevinRequest{
		SessionsDirectory: sessionsDirectory,
		WorkingDirectory:  workingDirectory,
		Terminal:          terminal,
		ResolvedPlan:      &resolved,
	})
	if err != nil {
		return exitCode, sanitizeLaunchError(err)
	}
	return exitCode, nil
}

// sanitizeLaunchError preserves stable public error matching while keeping
// lower executor runtime detail private and redacted.
func sanitizeLaunchError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	var preflightFailure *devinruntime.PreflightError
	if errors.As(err, &preflightFailure) {
		return &PreflightError{Capability: preflightFailure.Capability, runtime: preflightFailure}
	}
	var exit executor.DevinExit
	if errors.As(err, &exit) {
		return &DevinExitError{Code: exit.ExitCode()}
	}
	return &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

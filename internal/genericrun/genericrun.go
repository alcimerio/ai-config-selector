// Package genericrun is the public-command facade for literal contained argv.
package genericrun

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
)

type commandExecutor interface {
	Readiness(context.Context) (launch.SandboxReadiness, error)
	RunCommand(context.Context, executor.CommandRequest) (int, error)
}

type Target struct{ executor commandExecutor }

func New() *Target { return &Target{executor: executor.New()} }

func (target *Target) PlanLaunch(ctx context.Context, workingDirectory string, resolved category.ResolvedProfile, argv []string) (launch.Plan, error) {
	command, err := runcommand.Resolve(workingDirectory, argv)
	if err != nil {
		return launch.Plan{}, err
	}
	commandPlan, err := resolved.ForCommand()
	if err != nil {
		return launch.Plan{}, err
	}
	plan, err := commandPlan.Plan(ctx, workingDirectory)
	if err != nil {
		return launch.Plan{}, err
	}
	readiness, err := target.executor.Readiness(ctx)
	if err != nil {
		return launch.Plan{}, fmt.Errorf("inspect required process sandbox readiness: %w", err)
	}
	plan.Sections = append(plan.Sections,
		launch.PlanSection{Title: "Literal command:", Items: []launch.PlanItem{
			{Label: "executable form", Details: []launch.PlanDetail{{Label: "resolution", Value: string(command.Form())}}},
			{Label: "arguments", Details: []launch.PlanDetail{{Label: "literal child arguments", Value: fmt.Sprintf("%d (values hidden)", command.ArgumentCount())}}},
			{Label: "shell", Details: []launch.PlanDetail{{Label: "implicit evaluation", Value: "none"}}},
		}}, readinessSection(readiness))
	sanitizePlanPaths(&plan)
	return plan, nil
}

func sanitizePlanPaths(plan *launch.Plan) {
	for sectionIndex := range plan.Sections {
		for itemIndex := range plan.Sections[sectionIndex].Items {
			for detailIndex := range plan.Sections[sectionIndex].Items[itemIndex].Details {
				detail := &plan.Sections[sectionIndex].Items[itemIndex].Details[detailIndex]
				if filepath.IsAbs(detail.Value) {
					detail.Value = "(validated path hidden)"
				}
			}
		}
	}
}

func (target *Target) Launch(ctx context.Context, sessionsDirectory, workingDirectory string, resolved category.ResolvedProfile, argv []string, terminal launch.Terminal) (int, error) {
	command, err := runcommand.Resolve(workingDirectory, argv)
	if err != nil {
		return 1, sanitizeError(err)
	}
	commandPlan, err := resolved.ForCommand()
	if err != nil {
		return 1, sanitizeError(err)
	}
	code, err := target.executor.RunCommand(ctx, executor.CommandRequest{SessionsDirectory: sessionsDirectory,
		WorkingDirectory: workingDirectory, ResolvedPlan: &commandPlan, Command: command, Terminal: terminal})
	if err == nil {
		return code, nil
	}
	var ordinary interface{ ExitCode() int }
	if errors.As(err, &ordinary) {
		return ordinary.ExitCode(), &ExitError{Code: ordinary.ExitCode()}
	}
	if code == 130 && errors.Is(err, context.Canceled) {
		return 130, &ExitError{Code: 130}
	}
	return 1, sanitizeError(err)
}

func sanitizeError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	return &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

func readinessSection(readiness launch.SandboxReadiness) launch.PlanSection {
	platform, backend := "unsupported", "not ready"
	if readiness.Supported {
		platform = "supported"
	}
	if readiness.Ready {
		backend = "ready"
	} else if readiness.Failure != nil {
		backend += " (" + readiness.Failure.Error() + ")"
	}
	return launch.PlanSection{Title: "Sandbox readiness:", Items: []launch.PlanItem{
		{Label: "required sandbox mode: " + readiness.RequiredMode},
		{Label: "selected native backend: " + readiness.Backend},
		{Label: "supported platform: " + platform + " (" + readiness.Platform + ")"},
		{Label: "backend readiness: " + backend},
		{Label: "ACS will not start the requested command without the required sandbox."},
	}}
}

type ExitError struct{ Code int }

func (err *ExitError) Error() string { return fmt.Sprintf("command exited with status %d", err.Code) }
func (err *ExitError) ExitCode() int { return err.Code }

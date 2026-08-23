// Package sandboxshell launches a fixed interactive system shell inside an
// ephemeral ACS Session and the required native process sandbox.
package sandboxshell

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

const systemShell = "/bin/zsh"

// Launcher owns the target-independent Profile materialization and launches
// the fixed system shell through the native sandbox selected by ACS.
type Launcher struct {
	sandbox launch.ProcessSandbox
}

// New returns the production sandbox-shell launcher. The executable and
// sandbox backend cannot be selected or bypassed by callers.
func New() *Launcher {
	return newLauncher(launch.NewProcessSandbox())
}

func newLauncher(sandbox launch.ProcessSandbox) *Launcher {
	return &Launcher{sandbox: sandbox}
}

// Launch creates a credential-free Session, materializes the selected Profile,
// and runs /bin/zsh -f inside the required native sandbox.
func (launcher *Launcher) Launch(
	ctx context.Context,
	sessionsDirectory string,
	workingDirectory string,
	resolved category.ResolvedProfile,
	terminal launch.Terminal,
) (exitCode int, resultErr error) {
	if err := launcher.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: workingDirectory, SessionsDirectory: sessionsDirectory, Executable: systemShell,
	}); err != nil {
		return 1, err
	}

	createdSession, err := session.Create(sessionsDirectory, workingDirectory, resolved)
	if err != nil {
		return 1, sanitizeError(err)
	}
	defer func() {
		if err := createdSession.Remove(); err != nil {
			resultErr = sanitizeError(errors.Join(resultErr, err))
			exitCode = 1
		}
	}()

	process, err := launcher.sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace:          createdSession.WorkingDirectory(),
		SessionsDirectory:  createdSession.SessionsDirectory(),
		SessionDirectory:   createdSession.RootDirectory(),
		SessionHome:        createdSession.HomeDirectory(),
		TemporaryDirectory: createdSession.TemporaryDirectory(),
		Executable:         systemShell,
		Arguments:          []string{"-f"},
		Terminal:           terminal,
	})
	if err != nil {
		return 1, sanitizeError(err)
	}
	process, err = createdSession.RetainUntilProcessDone(process)
	if err != nil {
		return 1, sanitizeError(err)
	}
	if err := launch.RunAttached(process); err != nil {
		if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
			return 1, sanitizeError(cleanupErr)
		}
		var targetExit *exec.ExitError
		if errors.As(err, &targetExit) {
			if status, ok := targetExit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code := 128 + int(status.Signal())
				return code, &ExitError{Code: code}
			}
			if code := targetExit.ExitCode(); code >= 0 {
				return code, &ExitError{Code: code}
			}
		}
		return 1, sanitizeError(err)
	}
	return 0, nil
}

func sanitizeError(err error) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return sandboxFailure
	}
	return &launch.SandboxError{Category: launch.SandboxSetupFailed}
}

// PlanLaunch reports Profile contents and native sandbox readiness without
// creating a Session or starting a shell.
func (launcher *Launcher) PlanLaunch(ctx context.Context, workingDirectory string, resolved category.ResolvedProfile) (launch.Plan, error) {
	plan, err := resolved.Plan(ctx, workingDirectory)
	if err != nil {
		return launch.Plan{}, err
	}
	readiness, err := launcher.sandbox.Readiness(ctx)
	if err != nil {
		return launch.Plan{}, fmt.Errorf("inspect required process sandbox readiness: %w", err)
	}
	plan.Sections = append(plan.Sections, readinessSection(readiness))
	return plan, nil
}

func readinessSection(readiness launch.SandboxReadiness) launch.PlanSection {
	platform := "unsupported"
	if readiness.Supported {
		platform = "supported"
	}
	backend := "not ready"
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
		{Label: "ACS will not start a sandbox shell without the required sandbox."},
	}}
}

// ExitError preserves an ordinary sandbox-shell exit status through the CLI.
type ExitError struct{ Code int }

func (err *ExitError) Error() string {
	return fmt.Sprintf("sandbox shell exited with status %d", err.Code)
}
func (err *ExitError) ExitCode() int { return err.Code }

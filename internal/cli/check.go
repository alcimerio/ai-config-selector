package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
)

// CheckProbeOptions exposes validated opt-ins for narrow executable composition.
func CheckProbeOptions(args []string) (requested, native, authentication bool) {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && inv.command.path == "check", inv.secondEnabled, inv.thirdEnabled
}

// RunCheck owns optional active orchestration separately from passive diagnostics.
// Its report contains fixed sanitized facts, never provider messages or target output.
func (app App) RunCheck(ctx context.Context, args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || inv.command.path != "check" {
		return false, 0
	}
	result := diagnostics.LaunchCheck(ctx, inv.value, inv.auxValue, home)
	result = app.probeCheck(ctx, inv, result)

	if inv.enabled {
		if json.NewEncoder(app.Output).Encode(result) != nil {
			return true, 1
		}
	} else {
		fmt.Fprintln(app.Output, "Launch check (partial evidence, not full launch readiness):")
		for _, c := range result.Checks {
			fmt.Fprintf(app.Output, "  %s: %s (%s)\n    %s\n", c.ID, c.Status, c.Code, c.NextStep)
		}
	}
	return true, result.ExitCode()
}

func (app App) probeCheck(ctx context.Context, inv invocation, result diagnostics.Result) diagnostics.Result {
	probeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if inv.secondEnabled {
		result.SetFact("native.readiness", "unchecked", "prerequisites_required", "Correct host and backend facts before requesting native readiness.")
		if result.Passed("host.platform") && result.Passed("backend.file") {
			result.SetFact("native.readiness", "fail", "native_readiness_unavailable", "The native readiness owner is unavailable.")
			if app.NativeReadiness != nil && probeContext.Err() == nil {
				observation, err := app.NativeReadiness.Readiness(probeContext)
				if err == nil && observation.Supported && observation.Ready {
					result.SetFact("native.readiness", "pass", "native_backend_ready", "The bounded backend observation passed; generated policy and target launch remain unchecked.")
				} else {
					result.SetFact("native.readiness", "fail", "native_readiness_failed", "The bounded native readiness observation failed; inspect acs doctor and retry on a supported host.")
				}
			}
		}
	}
	if inv.thirdEnabled {
		result.SetFact("authentication", "unchecked", "prerequisites_required", "Correct Profile, source, overlay, host, backend and executable facts before probing the named identity.")
		result.SetFact("executable.version", "unchecked", "status_not_started", "Version is checked only inside the explicitly requested authentication status operation.")
		if result.ExitCode() == 0 && result.Passed("profile.overlays") && result.Passed("executable.availability") {
			result.SetFact("authentication", "fail", "authentication_status_unavailable", "The contained authentication status owner is unavailable.")
			status := app.CheckAuthentication
			if status == nil && app.CodexAuth != nil {
				status = app.CodexAuth.Status
			}
			if status != nil && probeContext.Err() == nil {
				_, err := status(probeContext, inv.thirdValue)
				switch {
				case err == nil:
					result.SetFact("executable.version", "pass", "supported_status_version", "The contained status operation verified the exact supported target version.")
					result.SetFact("authentication", "pass", "named_status_passed", "The explicitly named identity passed contained status and cleanup; eligible same-identity refresh may have been committed.")
				case errors.Is(err, codexauth.ErrUnsupportedVersion):
					result.SetFact("executable.version", "fail", "unsupported_status_version", "Install the exact supported target version documented by acs codex auth --help.")
					result.SetFact("authentication", "unchecked", "version_required", "Authentication was not established because target version verification failed.")
				default:
					result.SetFact("authentication", "fail", "named_status_failed", "Contained status failed; inspect the named authentication workflow. No login or recovery was attempted; uncertain Sessions remain preserved.")
					result.SetFact("executable.version", "unchecked", "status_version_unconfirmed", "A failed status operation does not expose completed version evidence.")
				}
			}
		}
	}
	if ctx.Err() != nil || probeContext.Err() != nil {
		result.SetFact("operation.completion", "fail", "cancelled", "The check was cancelled or reached its bounded probe deadline; retry when ready.")
	}
	return result
}

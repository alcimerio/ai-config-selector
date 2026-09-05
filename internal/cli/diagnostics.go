package cli

import (
	"encoding/json"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
)

// RunDiagnostics dispatches before Adapter, authentication, cwd and Session setup.
func (app App) RunDiagnostics(args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || (inv.command.path != "doctor" && inv.command.path != "profile validate") {
		return false, 0
	}
	var result diagnostics.Result
	if inv.command.path == "doctor" {
		result = diagnostics.Doctor(inv.value)
	} else {
		result = diagnostics.Validate(inv.value, home)
	}
	if inv.enabled {
		if json.NewEncoder(app.Output).Encode(result) != nil {
			return true, 1
		}
	} else {
		fmt.Fprintln(app.Output, "Passive diagnostics (no processes executed or files changed):")
		for _, check := range result.Checks {
			fmt.Fprintf(app.Output, "  %s: %s (%s)\n    %s\n", check.ID, check.Status, check.Code, check.NextStep)
		}
	}
	return true, result.ExitCode()
}

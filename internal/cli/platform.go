package cli

import (
	"runtime"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// RunUnsupportedExecution rejects Linux execution before main constructs
// target or credential dependencies. Passive commands and dry-runs still use
// their normal paths, including structured readiness and doctor reports.
func (app App) RunUnsupportedExecution(args []string) (bool, int) {
	if runtime.GOOS != "linux" {
		return false, 0
	}
	inv, problem := parseCommand(args)
	if problem != "" || inv.help {
		return false, 0
	}
	switch inv.command.path {
	case "devin", "codex", "sandbox", "run":
		if inv.enabled {
			return false, 0
		}
	case "codex auth login", "codex auth status":
	default:
		return false, 0
	}
	return true, app.fail("%v", launch.ValidatePlatform(launch.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}))
}

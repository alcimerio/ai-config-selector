package cli

import (
	"runtime"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// RunUnsupportedExecution rejects unqualified Linux execution before main
// constructs target or credential dependencies. Qualified linux/amd64 continues
// into the sandbox. Passive commands and dry-runs still use their normal paths,
// including structured readiness and doctor reports.
func (app App) RunUnsupportedExecution(args []string) (bool, int) {
	if runtime.GOOS != "linux" {
		return false, 0
	}
	inv, problem := parseCommand(args)
	if problem != "" || inv.help {
		return false, 0
	}
	switch inv.command.path {
	case "devin", "codex", "grok", "sandbox", "run":
		if inv.enabled {
			return false, 0
		}
	case "codex auth login", "codex auth status":
	default:
		return false, 0
	}
	if err := launch.ValidatePlatform(launch.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}); err != nil {
		return true, app.fail("%v", err)
	}
	return false, 0
}

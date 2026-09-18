package cli

import (
	"context"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/selfupdate"
)

// RunUpdate is called before home, provider, or Session dependency construction.
func (app App) RunUpdate(ctx context.Context, args []string, cfg selfupdate.Config) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || inv.command.path != "update" {
		return false, 0
	}
	result, err := selfupdate.Run(ctx, app.Version, inv.operand, inv.enabled, cfg)
	if err != nil {
		fmt.Fprintf(app.ErrorOutput, "acs update: %v\n", err)
		return true, 1
	}
	if inv.enabled {
		if _, e := selfupdate.ParseVersion(result.Current); e != nil {
			fmt.Fprintf(app.Output, "Current: %s\nTarget: %s\nUpdate available: unknown (current build is not a numeric release)\n", result.Current, result.Target)
		} else {
			fmt.Fprintf(app.Output, "Current: %s\nTarget: %s\nUpdate available: %t\n", result.Current, result.Target, result.Available)
		}
		return true, 0
	}
	if !result.Changed {
		fmt.Fprintf(app.Output, "acs %s is already the latest published stable release\n", result.Current)
		return true, 0
	}
	fmt.Fprintf(app.Output, "Installed acs %s at %s\n", result.Target, result.Installation)
	if result.Downgrade {
		fmt.Fprintln(app.Output, "Older ACS may not support your current Profiles or data. The update did not change user data; see docs/manual-upgrade-recovery.md for backup and recovery guidance.")
	}
	return true, 0
}

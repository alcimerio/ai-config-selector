package cli

import (
	"fmt"
	"runtime"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
)

// RunCredentialProvider handles only provider configuration. It runs before
// target, credential-store, lock, quarantine, or Session construction.
func (app App) RunCredentialProvider(args []string) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || inv.command.path != "codex auth provider" {
		return false, 0
	}
	if inv.value != "" {
		if err := codexauthresource.SelectProvider(codexauthresource.ProviderID(inv.value)); err != nil {
			return true, app.fail("%v", err)
		}
	}
	provider, err := codexauthresource.SelectedProvider()
	if err != nil {
		return true, app.fail("%v", err)
	}
	fmt.Fprintf(app.Output, "Credential provider: %s\n", provider)
	if runtime.GOOS == "linux" {
		fmt.Fprintln(app.Output, "Linux credential operations and launches remain unavailable.")
	}
	return true, 0
}

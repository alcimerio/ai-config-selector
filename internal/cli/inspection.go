package cli

import (
	"encoding/json"
	"fmt"

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

// RunProfileInspection dispatches before adapter, auth, cwd and Session setup.
// Help and syntax must first pass RunInformational; no runtime dependency is
// needed, even when the home cannot be discovered.
func (app App) RunProfileInspection(args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || (inv.command.path != "profile list" && inv.command.path != "profile show") {
		return false, 0
	}
	// Store.Show validates names without opening storage. Route invalid operands
	// there before home discovery so their diagnostic does not depend on HOME.
	if inv.command.path == "profile show" && profile.ValidateName(inv.value) != nil {
		app.Inspector = profileinspect.Store{}
		return true, app.inspectProfiles(inv)
	}
	directory, err := home()
	if err == nil {
		app.Inspector = profileinspect.Store{Home: directory}
	}
	return true, app.inspectProfiles(inv)
}
func (app App) inspectProfiles(inv invocation) int {
	operation := "list"
	if inv.command.path == "profile show" {
		operation = "show"
	}
	result := profileinspect.Unavailable(operation)
	if app.Inspector != nil {
		if operation == "list" {
			result = app.Inspector.List()
		} else {
			result = app.Inspector.Show(inv.value)
		}
	}
	if inv.enabled {
		if err := json.NewEncoder(app.Output).Encode(result); err != nil {
			return 1
		}
	} else {
		fmt.Fprintln(app.Output, "Stored Profiles (structure only; sources, authentication and runtime unchecked):")
		if result.Diagnostic != nil {
			fmt.Fprintf(app.Output, "  %s: %s\n", result.Diagnostic.Code, result.Diagnostic.Message)
		}
		if result.Diagnostic == nil && len(result.Entries) == 0 {
			fmt.Fprintln(app.Output, "  (none)\nCreate a Profile with: acs devin create-profile --name NAME")
		}
		for _, entry := range result.Entries {
			name := "(invalid name)"
			if entry.Name != nil {
				name = *entry.Name
			}
			fmt.Fprintf(app.Output, "  %s: %s\n", safeTerminalText(name), entry.Status)
			if entry.File != nil {
				fmt.Fprintf(app.Output, "    file: %s\n", *entry.File)
			}
			if entry.Diagnostic != nil {
				fmt.Fprintf(app.Output, "    %s: %s\n", entry.Diagnostic.Code, entry.Diagnostic.Message)
				continue
			}
			fmt.Fprintf(app.Output, "    stored version: %d; target: %s\n", *entry.StoredVersion, *entry.Target)
			for _, category := range entry.Categories {
				schema := "legacy (no category envelope)"
				if category.SchemaVersion != nil {
					schema = fmt.Sprint(*category.SchemaVersion)
				}
				fmt.Fprintf(app.Output, "    %s: %d selected; stored category version: %s\n", category.ID, len(category.Selection), schema)
				if operation == "show" {
					for _, reference := range category.Selection {
						fmt.Fprintf(app.Output, "      %s: %s\n", safeTerminalText(string(reference.Source)), safeTerminalText(reference.RelativePath))
					}
				}
			}
		}
	}
	return result.ExitCode()
}

// Package cli implements the public ACS command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type ProfileDraftEditor interface {
	EditProfileDraft(context.Context, category.Draft, io.Reader, io.Writer) (category.Draft, error)
}

type ProfileStore interface {
	Create(profile.Profile) (string, error)
	Load(string) (profile.Profile, error)
}

type LaunchPlanner interface {
	PlanLaunch(context.Context, string, category.ResolvedProfile) (launch.Plan, error)
}

type ProfileLauncher interface {
	Launch(context.Context, string, string, category.ResolvedProfile, launch.Terminal) (int, error)
}

type App struct {
	Categories        *category.Registry
	DraftEditor       ProfileDraftEditor
	Planner           LaunchPlanner
	Launcher          ProfileLauncher
	Profiles          ProfileStore
	SessionsDirectory string
	WorkingDirectory  string
	Input             io.Reader
	Output            io.Writer
	ErrorOutput       io.Writer
}

func (app App) Run(ctx context.Context, args []string) int {
	if len(args) == 4 && args[0] == "devin" && args[1] == "create-profile" && args[2] == "--name" && args[3] != "" {
		return app.createProfile(ctx, args[3])
	}
	if len(args) == 4 && args[0] == "devin" && args[1] == "--profile" && args[2] != "" && args[3] == "--dry-run" {
		return app.dryRun(ctx, args[2])
	}
	if len(args) == 3 && args[0] == "devin" && args[1] == "--profile" && args[2] != "" {
		return app.launchProfile(ctx, args[2])
	}
	return app.fail("usage: acs devin create-profile --name <name> | acs devin --profile <name> [--dry-run]")
}

func (app App) createProfile(ctx context.Context, name string) int {
	if err := profile.ValidateName(name); err != nil {
		return app.fail("%v", err)
	}

	draft := app.Categories.NewDraft()
	fmt.Fprintf(app.Output, "Create Profile %q\n\n", name)
	edited, err := app.DraftEditor.EditProfileDraft(ctx, draft, app.Input, app.Output)
	if err != nil {
		return app.fail("edit Profile %q: %v", name, err)
	}
	created, err := app.Categories.NewProfile(name, edited)
	if err != nil {
		return app.fail("build Profile %q: %v", name, err)
	}
	path, err := app.Profiles.Create(created)
	if err != nil {
		return app.fail("create Profile %q: %v", created.Name, err)
	}
	selectedCount := 0
	for _, summary := range edited.Summaries() {
		selectedCount += summary.Count
	}
	fmt.Fprintf(app.Output, "\nCreated Profile %q with %d selected items at %s\n", created.Name, selectedCount, safeTerminalText(path))
	return 0
}

func (app App) dryRun(ctx context.Context, name string) int {
	resolved, err := app.resolveProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	plan, err := app.Planner.PlanLaunch(ctx, app.WorkingDirectory, resolved)
	if err != nil {
		return app.fail("plan Profile %q launch: %v", name, err)
	}

	fmt.Fprintf(app.Output, "Dry run for Profile %q\n", name)
	for _, section := range plan.Sections {
		fmt.Fprintln(app.Output, "\n"+safeTerminalText(section.Title))
		if len(section.Items) == 0 {
			fmt.Fprintln(app.Output, "  (none)")
		}
		for _, item := range section.Items {
			fmt.Fprintf(app.Output, "  %s\n", safeTerminalText(item.Label))
			for _, detail := range item.Details {
				fmt.Fprintf(app.Output, "    %s: %s\n", safeTerminalText(detail.Label), safeTerminalText(detail.Value))
			}
		}
	}
	fmt.Fprintln(app.Output, "\nNo Session was created and Devin was not started.")
	return 0
}

func (app App) launchProfile(ctx context.Context, name string) int {
	resolved, err := app.resolveProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	exitCode, err := app.Launcher.Launch(
		ctx,
		app.SessionsDirectory,
		app.WorkingDirectory,
		resolved,
		launch.Terminal{Input: app.Input, Output: app.Output, ErrorOutput: app.ErrorOutput},
	)
	if err != nil {
		return app.fail("launch Profile %q: %v", name, err)
	}
	return exitCode
}

func (app App) resolveProfile(ctx context.Context, name string) (category.ResolvedProfile, error) {
	if err := profile.ValidateName(name); err != nil {
		return category.ResolvedProfile{}, err
	}
	loaded, err := app.Profiles.Load(name)
	if err != nil {
		return category.ResolvedProfile{}, fmt.Errorf("load Profile %q: %w", name, err)
	}
	resolved, err := app.Categories.Resolve(ctx, loaded)
	if err != nil {
		return category.ResolvedProfile{}, fmt.Errorf("resolve Profile %q: %w", name, err)
	}
	return resolved, nil
}

func (app App) fail(format string, arguments ...any) int {
	fmt.Fprintf(app.ErrorOutput, "acs: "+format+"\n", arguments...)
	return 1
}

func safeTerminalText(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

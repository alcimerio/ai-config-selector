// Package cli implements the public ACS command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type ProfileDraftEditor interface {
	EditProfileDraft(context.Context, category.Draft, io.Reader, io.Writer) (category.Draft, error)
}

// ProfileBuilder owns the terminal UI and returns its post-terminal outcome.
type ProfileBuilder interface {
	BuildProfile(context.Context, string, category.Draft, io.Reader, io.Writer) (builder.Outcome, error)
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
	Builder           ProfileBuilder
	DraftEditor       ProfileDraftEditor
	Planner           LaunchPlanner
	Launcher          ProfileLauncher
	Profiles          ProfileStore
	SessionsDirectory string
	WorkingDirectory  string
	Input             io.Reader
	Output            io.Writer
	ErrorOutput       io.Writer
	Interactive       func(io.Reader, io.Writer) bool
}

// StandardStreamsInteractive reports whether both endpoints are terminal
// devices. Callers can inject a narrower capability check in tests.
func StandardStreamsInteractive(input io.Reader, output io.Writer) bool {
	inputFile, inputIsFile := input.(*os.File)
	outputFile, outputIsFile := output.(*os.File)
	if !inputIsFile || !outputIsFile {
		return false
	}
	inputInfo, inputErr := inputFile.Stat()
	outputInfo, outputErr := outputFile.Stat()
	return inputErr == nil && outputErr == nil && inputInfo.Mode()&os.ModeCharDevice != 0 && outputInfo.Mode()&os.ModeCharDevice != 0
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
	if _, err := app.Profiles.Load(name); err == nil {
		return app.fail("create Profile %q: %v: %q", name, profile.ErrProfileExists, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return app.fail("check Profile %q: %v", name, err)
	}

	draft := app.Categories.NewDraft()
	if app.Builder != nil {
		if app.Interactive == nil || !app.Interactive(app.Input, app.Output) {
			return app.fail("create Profile requires interactive stdin and stdout")
		}
		outcome, err := app.Builder.BuildProfile(ctx, name, draft, app.Input, app.Output)
		if err != nil {
			return app.fail("edit Profile %q: %v", name, err)
		}
		if outcome.Cancelled {
			return 0
		}
		if !outcome.Create {
			return app.fail("edit Profile %q: Profile Builder ended without an outcome", name)
		}
		draft = outcome.Draft
	} else {
		fmt.Fprintf(app.Output, "Create Profile %q\n\n", name)
		edited, err := app.DraftEditor.EditProfileDraft(ctx, draft, app.Input, app.Output)
		if err != nil {
			return app.fail("edit Profile %q: %v", name, err)
		}
		draft = edited
	}
	created, err := app.Categories.NewProfile(name, draft)
	if err != nil {
		return app.fail("build Profile %q: %v", name, err)
	}
	path, err := app.Profiles.Create(created)
	if err != nil {
		return app.fail("create Profile %q: %v", created.Name, err)
	}
	selectedCount := 0
	for _, summary := range draft.Summaries() {
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

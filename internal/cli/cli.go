// Package cli implements the public ACS command-line interface.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type SkillCatalog interface {
	DiscoverGlobalSkillCatalog(context.Context) ([]skills.SkillBundle, error)
}

type ProfileStore interface {
	Create(profile.Profile) (string, error)
	Load(string) (profile.Profile, error)
}

type LaunchPlanner interface {
	PlanLaunch(context.Context, string, []skills.SkillBundle) (launch.Plan, error)
}

type ProfileLauncher interface {
	Launch(context.Context, string, string, []skills.SkillBundle, launch.Terminal) (int, error)
}

type App struct {
	Catalog           SkillCatalog
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

	bundles, err := app.Catalog.DiscoverGlobalSkillCatalog(ctx)
	if err != nil {
		return app.fail("discover Devin global Skill Catalog: %v", err)
	}

	fmt.Fprintf(app.Output, "Create Profile %q\n\nSelect global Skill Bundles:\n", name)
	for index, bundle := range bundles {
		fmt.Fprintf(
			app.Output,
			"  %d. %s [%s] %s\n",
			index+1,
			safeTerminalText(bundle.DisplayName),
			safeTerminalText(string(bundle.Reference.Source)),
			safeTerminalText(bundle.BundlePath),
		)
	}
	fmt.Fprint(app.Output, "\nEnter comma-separated numbers (blank for none): ")

	reader := bufio.NewReader(app.Input)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return app.fail("read selection: %v", err)
	}
	selected, err := parseSelection(strings.TrimSpace(line), bundles)
	if err != nil {
		return app.fail("invalid selection: %v", err)
	}
	if len(selected) == 0 {
		fmt.Fprint(app.Output, "Create an empty Profile? [y/N] ")
		confirmation, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return app.fail("read empty Profile confirmation: %v", readErr)
		}
		answer := strings.ToLower(strings.TrimSpace(confirmation))
		if answer != "y" && answer != "yes" {
			return app.fail("empty Profile was not confirmed; Profile not created")
		}
	}

	references := make([]skills.SkillReference, 0, len(selected))
	for _, bundle := range selected {
		references = append(references, bundle.Reference)
	}
	created := profile.Profile{
		Version:         profile.CurrentVersion,
		Name:            name,
		Target:          "devin",
		SkillReferences: references,
	}
	path, err := app.Profiles.Create(created)
	if err != nil {
		return app.fail("create Profile %q: %v", created.Name, err)
	}
	fmt.Fprintf(app.Output, "\nCreated Profile %q with %d Skill Bundles at %s\n", created.Name, len(references), safeTerminalText(path))
	return 0
}

func (app App) dryRun(ctx context.Context, name string) int {
	selected, err := app.resolveDevinProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	plan, err := app.Planner.PlanLaunch(ctx, app.WorkingDirectory, selected)
	if err != nil {
		return app.fail("plan Profile %q launch: %v", name, err)
	}

	fmt.Fprintf(app.Output, "Dry run for Profile %q\n\nSelected global Skill Bundles managed by ACS:\n", name)
	if len(plan.SelectedGlobalSkillBundles) == 0 {
		fmt.Fprintln(app.Output, "  (none)")
	}
	for _, planned := range plan.SelectedGlobalSkillBundles {
		fmt.Fprintf(
			app.Output,
			"  %s [%s]\n    source: %s\n    Session: %s\n",
			safeTerminalText(planned.Bundle.DisplayName),
			safeTerminalText(string(planned.Bundle.Reference.Source)),
			safeTerminalText(planned.Bundle.BundlePath),
			safeTerminalText(planned.SessionPath),
		)
	}
	fmt.Fprintln(app.Output, "\nProject-local Skill Bundles inherited by Devin (not managed by ACS):")
	if len(plan.ProjectLocalSkillBundles) == 0 {
		fmt.Fprintln(app.Output, "  (none)")
	}
	for _, bundle := range plan.ProjectLocalSkillBundles {
		fmt.Fprintf(app.Output, "  %s %s\n", safeTerminalText(bundle.DisplayName), safeTerminalText(bundle.BundlePath))
	}
	fmt.Fprintln(app.Output, "\nNo Session was created and Devin was not started.")
	return 0
}

func (app App) launchProfile(ctx context.Context, name string) int {
	selected, err := app.resolveDevinProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	exitCode, err := app.Launcher.Launch(
		ctx,
		app.SessionsDirectory,
		app.WorkingDirectory,
		selected,
		launch.Terminal{Input: app.Input, Output: app.Output, ErrorOutput: app.ErrorOutput},
	)
	if err != nil {
		return app.fail("launch Profile %q: %v", name, err)
	}
	return exitCode
}

func (app App) resolveDevinProfile(ctx context.Context, name string) ([]skills.SkillBundle, error) {
	if err := profile.ValidateName(name); err != nil {
		return nil, err
	}
	loaded, err := app.Profiles.Load(name)
	if err != nil {
		return nil, fmt.Errorf("load Profile %q: %w", name, err)
	}
	if loaded.Target != "devin" {
		return nil, fmt.Errorf("Profile %q targets %q, not Devin", name, loaded.Target)
	}
	if loaded.Version != profile.CurrentVersion {
		return nil, fmt.Errorf("Profile %q uses unsupported schema version %d", name, loaded.Version)
	}
	catalog, err := app.Catalog.DiscoverGlobalSkillCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover Devin global Skill Catalog: %w", err)
	}
	selected, err := skills.ResolveReferences(loaded.SkillReferences, catalog)
	if err != nil {
		return nil, fmt.Errorf("resolve Profile %q: %w", name, err)
	}
	return selected, nil
}

func (app App) fail(format string, arguments ...any) int {
	fmt.Fprintf(app.ErrorOutput, "acs: "+format+"\n", arguments...)
	return 1
}

func parseSelection(input string, catalog []skills.SkillBundle) ([]skills.SkillBundle, error) {
	if input == "" {
		return nil, nil
	}
	selected := make([]skills.SkillBundle, 0)
	seen := make(map[int]bool)
	for _, rawIndex := range strings.Split(input, ",") {
		index, err := strconv.Atoi(strings.TrimSpace(rawIndex))
		if err != nil || index < 1 || index > len(catalog) {
			return nil, fmt.Errorf("%q is not a displayed Skill Bundle number", rawIndex)
		}
		if !seen[index] {
			selected = append(selected, catalog[index-1])
			seen[index] = true
		}
	}
	return selected, nil
}

func safeTerminalText(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

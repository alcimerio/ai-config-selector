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

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type SkillCatalog interface {
	DiscoverGlobalSkillCatalog(context.Context) ([]skills.SkillBundle, error)
}

type ProfileCreator interface {
	Create(profile.Profile) (string, error)
}

type App struct {
	Catalog     SkillCatalog
	Profiles    ProfileCreator
	Input       io.Reader
	Output      io.Writer
	ErrorOutput io.Writer
}

func (app App) Run(ctx context.Context, args []string) int {
	if len(args) != 4 || args[0] != "devin" || args[1] != "create-profile" || args[2] != "--name" || args[3] == "" {
		return app.fail("usage: acs devin create-profile --name <name>")
	}
	if err := profile.ValidateName(args[3]); err != nil {
		return app.fail("%v", err)
	}

	bundles, err := app.Catalog.DiscoverGlobalSkillCatalog(ctx)
	if err != nil {
		return app.fail("discover Devin global Skill Catalog: %v", err)
	}

	fmt.Fprintf(app.Output, "Create Profile %q\n\nSelect global Skill Bundles:\n", args[3])
	for index, bundle := range bundles {
		fmt.Fprintf(
			app.Output,
			"  %d. %s [%s] %s\n",
			index+1,
			safeTerminalText(bundle.DisplayName),
			safeTerminalText(string(bundle.Reference.Source)),
			safeTerminalText(bundle.Path),
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
		Name:            args[3],
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

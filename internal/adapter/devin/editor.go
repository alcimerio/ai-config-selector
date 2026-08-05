package devin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// BuildProfile runs the first complete Profile Builder using this adapter's
// typed Skills category. The root model is the only Bubble Tea program.
func (a *Adapter) BuildProfile(ctx context.Context, name string, draft category.Draft, save builder.SaveFunc, input io.Reader, output io.Writer) (builder.Outcome, error) {
	model, err := builder.NewModel(name, draft, a.editors)
	if err != nil {
		return builder.Outcome{}, err
	}
	return builder.Run(ctx, model.WithSaver(save), input, output)
}

func newEditorRegistry(adapter *Adapter) (*builder.EditorRegistry, error) {
	registration, err := builder.RegisterSkillsEditor(adapter.skillsCategory, adapter.DiscoverGlobalSkillCatalog)
	if err != nil {
		return nil, err
	}
	return builder.NewEditorRegistry(adapter.categories, registration)
}

// EditProfileDraft presents the current line-oriented Skills editor. The
// category-neutral CLI delegates editing here until the interactive category
// navigator replaces this temporary UI.
func (a *Adapter) EditProfileDraft(ctx context.Context, draft category.Draft, input io.Reader, output io.Writer) (category.Draft, error) {
	bundles, err := a.DiscoverGlobalSkillCatalog(ctx)
	if err != nil {
		return draft, fmt.Errorf("discover Devin global Skill Catalog: %w", err)
	}

	fmt.Fprintln(output, "Select global Skill Bundles:")
	for index, bundle := range bundles {
		fmt.Fprintf(output, "  %d. %s [%s] %s\n", index+1, safeTerminalText(bundle.DisplayName), safeTerminalText(string(bundle.Reference.Source)), safeTerminalText(bundle.BundlePath))
	}
	fmt.Fprint(output, "\nEnter comma-separated numbers (blank for none): ")
	reader := bufio.NewReader(input)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return draft, fmt.Errorf("read selection: %w", err)
	}
	selected, err := parseSelection(strings.TrimSpace(line), bundles)
	if err != nil {
		return draft, fmt.Errorf("invalid selection: %w", err)
	}
	if len(selected) == 0 {
		fmt.Fprint(output, "Create an empty Profile? [y/N] ")
		confirmation, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return draft, fmt.Errorf("read empty Profile confirmation: %w", readErr)
		}
		answer := strings.ToLower(strings.TrimSpace(confirmation))
		if answer != "y" && answer != "yes" {
			return draft, errors.New("empty Profile was not confirmed; Profile not created")
		}
	}
	references := make([]skills.SkillReference, 0, len(selected))
	for _, bundle := range selected {
		references = append(references, bundle.Reference)
	}
	if err := category.SetSelection(&draft, a.skillsCategory, references); err != nil {
		return draft, err
	}
	return draft, nil
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

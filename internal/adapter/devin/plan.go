package devin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// PlanLaunch describes the selected global Skill Bundles and repository-local
// Skill Bundles Devin may inherit without creating a Session.
func (a *Adapter) PlanLaunch(ctx context.Context, workingDirectory string, resolved category.ResolvedProfile) (launch.Plan, error) {
	return resolved.Plan(ctx, workingDirectory)
}

func (a *Adapter) planSkills(ctx context.Context, workingDirectory string, selected []skills.SkillBundle, plan *launch.Plan) error {
	selectedSection := launch.PlanSection{
		Title: "Selected global Skill Bundles managed by ACS:",
		Items: make([]launch.PlanItem, 0, len(selected)),
	}
	for _, bundle := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, sessionPath, err := bundlePlacement(filepath.Join("<session>", "home"), bundle.Reference)
		if err != nil {
			return fmt.Errorf("plan Devin launch: %w", err)
		}
		selectedSection.Items = append(selectedSection.Items, launch.PlanItem{
			Label: fmt.Sprintf("%s [%s]", bundle.DisplayName, bundle.Reference.Source),
			Details: []launch.PlanDetail{
				{Label: "source", Value: bundle.BundlePath},
				{Label: "Session", Value: sessionPath},
			},
		})
	}

	projectSection := launch.PlanSection{
		Title: "Project-local Skill Bundles inherited by Devin (not managed by ACS):",
	}
	for _, relativeRoot := range projectSourceDirectories {
		root := filepath.Join(workingDirectory, relativeRoot)
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect Devin project-local skill source %q: %w", relativeRoot, err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			bundlePath := filepath.Join(root, entry.Name())
			bundleInfo, err := os.Stat(bundlePath)
			if err != nil || !bundleInfo.IsDir() {
				continue
			}
			manifest, err := os.Stat(filepath.Join(bundlePath, "SKILL.md"))
			if err != nil || !manifest.Mode().IsRegular() {
				continue
			}
			projectSection.Items = append(projectSection.Items, launch.PlanItem{
				Label: entry.Name() + " " + bundlePath,
			})
		}
	}
	plan.Sections = append(plan.Sections, selectedSection, projectSection)
	return nil
}

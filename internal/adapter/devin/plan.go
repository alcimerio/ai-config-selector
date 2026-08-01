package devin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// PlanLaunch describes the selected global Skill Bundles and repository-local
// Skill Bundles Devin may inherit without creating a Session.
func (a *Adapter) PlanLaunch(ctx context.Context, workingDirectory string, selected []skills.SkillBundle) (launch.Plan, error) {
	plan := launch.Plan{
		SelectedGlobalSkillBundles: make([]launch.SelectedGlobalSkillBundle, 0, len(selected)),
	}
	for _, bundle := range selected {
		if err := ctx.Err(); err != nil {
			return launch.Plan{}, err
		}
		_, sessionPath, err := bundlePlacement(filepath.Join("<session>", "home"), bundle.Reference)
		if err != nil {
			return launch.Plan{}, fmt.Errorf("plan Devin launch: %w", err)
		}
		plan.SelectedGlobalSkillBundles = append(plan.SelectedGlobalSkillBundles, launch.SelectedGlobalSkillBundle{
			Bundle:      bundle,
			SessionPath: sessionPath,
		})
	}

	for _, relativeRoot := range projectSourceDirectories {
		root := filepath.Join(workingDirectory, relativeRoot)
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return launch.Plan{}, fmt.Errorf("inspect Devin project-local skill source %q: %w", relativeRoot, err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return launch.Plan{}, err
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
			plan.ProjectLocalSkillBundles = append(plan.ProjectLocalSkillBundles, launch.ProjectLocalSkillBundle{
				DisplayName: entry.Name(),
				BundlePath:  bundlePath,
			})
		}
	}
	return plan, nil
}

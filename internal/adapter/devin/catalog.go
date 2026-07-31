package devin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// DiscoverGlobalSkillCatalog returns selectable Skill Bundles from only the
// explicit Devin user-global source rules. Project-local skills are excluded.
func (a *Adapter) DiscoverGlobalSkillCatalog(ctx context.Context) ([]skills.SkillBundle, error) {
	catalog := make([]skills.SkillBundle, 0)
	for _, rule := range globalSourceRules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sourceRoot := filepath.Join(a.existingHomeDir, rule.RelativeDirectory)
		entries, err := os.ReadDir(sourceRoot)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read Devin global skill source %q: %w", rule.Source, err)
		}

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			bundlePath := filepath.Join(sourceRoot, entry.Name())
			bundleInfo, err := os.Stat(bundlePath)
			if err != nil || !bundleInfo.IsDir() {
				continue
			}
			skillManifest, err := os.Stat(filepath.Join(bundlePath, "SKILL.md"))
			if err != nil || !skillManifest.Mode().IsRegular() {
				continue
			}

			catalog = append(catalog, skills.SkillBundle{
				Reference: skills.SkillReference{
					Source:       rule.Source,
					RelativePath: entry.Name(),
				},
				DisplayName: entry.Name(),
				SourceRoot:  sourceRoot,
				Path:        bundlePath,
			})
		}
	}

	sort.Slice(catalog, func(left, right int) bool {
		if catalog[left].DisplayName != catalog[right].DisplayName {
			return catalog[left].DisplayName < catalog[right].DisplayName
		}
		if catalog[left].Reference.Source != catalog[right].Reference.Source {
			return catalog[left].Reference.Source < catalog[right].Reference.Source
		}
		return catalog[left].Reference.RelativePath < catalog[right].Reference.RelativePath
	})
	return catalog, nil
}

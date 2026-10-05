// Package skillcatalog inspects source metadata without process or persistence capabilities.
package skillcatalog

import (
	"context"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"os"
	"path/filepath"
	"sort"
)

func DiscoverSelected(ctx context.Context, home string, references []skills.SkillReference) ([]skills.SkillBundle, error) {
	selected := map[skills.Source]bool{}
	for _, ref := range references {
		selected[ref.Source] = true
	}
	return DiscoverReport(ctx, home, selected, nil)
}
func DiscoverReport(ctx context.Context, home string, selected map[skills.Source]bool, unavailable map[skills.Source]bool) ([]skills.SkillBundle, error) {
	catalog := make([]skills.SkillBundle, 0)
	for _, rule := range devinruntime.GlobalSourceRules() {
		if selected != nil && !selected[rule.Source] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sourceRoot := filepath.Join(home, rule.RelativeDirectory)
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
			if err != nil && !os.IsNotExist(err) && unavailable != nil {
				unavailable[rule.Source] = true
			}
			if err != nil || !bundleInfo.IsDir() {
				continue
			}
			skillManifest, err := os.Stat(filepath.Join(bundlePath, "SKILL.md"))
			if err != nil && !os.IsNotExist(err) && unavailable != nil {
				unavailable[rule.Source] = true
			}
			if err != nil || !skillManifest.Mode().IsRegular() {
				continue
			}

			catalog = append(catalog, skills.SkillBundle{
				Reference: skills.SkillReference{
					Source:       rule.Source,
					RelativePath: entry.Name(),
				},
				DisplayName: entry.Name(),
				BundlePath:  bundlePath,
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

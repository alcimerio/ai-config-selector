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
	return discoverSkillCatalog(ctx, a.existingHomeDir, nil)
}

// DiscoverSelectedSkillCatalog uses the same discovery rules as launch, restricted
// to sources actually selected by validation. It creates no Adapter or Session.
func DiscoverSelectedSkillCatalog(ctx context.Context, home string, references []skills.SkillReference) ([]skills.SkillBundle, error) {
	selected := make(map[skills.Source]bool)
	for _, reference := range references {
		selected[reference.Source] = true
	}
	return discoverSkillCatalog(ctx, home, selected)
}

func discoverSkillCatalog(ctx context.Context, home string, selected map[skills.Source]bool) ([]skills.SkillBundle, error) {
	return discoverSkillCatalogReport(ctx, home, selected, nil)
}

func discoverSkillCatalogReport(ctx context.Context, home string, selected map[skills.Source]bool, unavailable map[skills.Source]bool) ([]skills.SkillBundle, error) {
	catalog := make([]skills.SkillBundle, 0)
	for _, rule := range globalSourceRules {
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

// discoverProfileSkills preserves successful sources when another source cannot
// be inspected. Launch and passive validation retain their existing semantics.
func (a *Adapter) discoverProfileSkills(ctx context.Context) (skills.Discovery, error) {
	result := skills.Discovery{UnavailableSources: map[skills.Source]bool{}}
	for _, rule := range globalSourceRules {
		catalog, err := discoverSkillCatalogReport(ctx, a.existingHomeDir, map[skills.Source]bool{rule.Source: true}, result.UnavailableSources)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.UnavailableSources[rule.Source] = true
		}
		result.Bundles = append(result.Bundles, catalog...)
	}
	return result, nil
}

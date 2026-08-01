package devin

import (
	"fmt"
	"path/filepath"
)

func bundlePlacement(sessionHome string, reference SkillReference) (SkillReference, string, error) {
	rule, ok := sourceRule(reference.Source)
	if !ok {
		return SkillReference{}, "", fmt.Errorf("unsupported global source %q", reference.Source)
	}
	relativePath, err := cleanBundleRelativePath(reference.RelativePath)
	if err != nil {
		return SkillReference{}, "", err
	}
	normalized := SkillReference{Source: reference.Source, RelativePath: relativePath}
	return normalized, filepath.Join(sessionHome, rule.RelativeDirectory, relativePath), nil
}

package devin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestCategoryRegistryNormalizesResolvesPlansAndMaterializesSkills(t *testing.T) {
	existingHome := t.TempDir()
	bundlePath := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	if err := os.MkdirAll(bundlePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	acsHome := filepath.Join(existingHome, ".acs")
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(acsHome, adapter.Categories())
	path, err := store.Create(devin.NewSkillsProfile("reviews", []skills.SkillReference{{Source: devin.GlobalSourceDevinConfig, RelativePath: "review"}}))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load("reviews")
	if err != nil {
		t.Fatalf("load Profile: %v", err)
	}
	resolved, err := adapter.Categories().Resolve(context.Background(), loaded)
	if err != nil {
		t.Fatalf("resolve Profile: %v", err)
	}
	plan, err := resolved.Plan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("plan Profile: %v", err)
	}
	if len(plan.Sections) < 2 || plan.Sections[0].Title != "Resolved execution authority:" {
		t.Fatalf("plan sections = %#v", plan.Sections)
	}
	var skillsSection *launch.PlanSection
	for index := range plan.Sections {
		if plan.Sections[index].Title == "Selected common Skill Bundles:" {
			skillsSection = &plan.Sections[index]
		}
	}
	if skillsSection == nil || len(skillsSection.Items) != 1 || skillsSection.Items[0].Details[0].Value != "devin-config:review" {
		t.Fatalf("selected common Skill plan = %#v", plan.Sections)
	}

	sessionHome := filepath.Join(t.TempDir(), "home")
	if err := resolved.Materialize(sessionHome); err != nil {
		t.Fatalf("materialize Profile: %v", err)
	}
	for _, copiedPath := range []string{
		filepath.Join(sessionHome, ".acs", "common", "v1", "skills", "devin-config", "review", "SKILL.md"),
		filepath.Join(sessionHome, ".config", "devin", "skills", "review", "SKILL.md"),
	} {
		copied, err := os.ReadFile(copiedPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(copied) != "# review\n" {
			t.Fatalf("copied Skill manifest %s = %q", copiedPath, copied)
		}
	}
	afterLoad, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterLoad, stored) {
		t.Fatalf("Profile was rewritten: %s", afterLoad)
	}
}

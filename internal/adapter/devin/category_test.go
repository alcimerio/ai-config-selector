package devin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/profile"
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
	legacy := []byte(`{"version":1,"name":"reviews","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"review"}]}`)
	legacyPath := filepath.Join(profilesDirectory, "reviews.json")
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := profile.NewStore(acsHome, adapter.Categories()).Load("reviews")
	if err != nil {
		t.Fatalf("load legacy Profile: %v", err)
	}
	resolved, err := adapter.Categories().Resolve(context.Background(), loaded)
	if err != nil {
		t.Fatalf("resolve Profile: %v", err)
	}
	plan, err := resolved.Plan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("plan Profile: %v", err)
	}
	if len(plan.Sections) != 2 || len(plan.Sections[0].Items) != 1 || plan.Sections[0].Items[0].Details[0].Value != bundlePath {
		t.Fatalf("selected global Skill plan = %#v", plan.Sections)
	}

	sessionHome := filepath.Join(t.TempDir(), "home")
	if err := resolved.Materialize(sessionHome); err != nil {
		t.Fatalf("materialize Profile: %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(sessionHome, ".config", "devin", "skills", "review", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != "# review\n" {
		t.Fatalf("copied Skill manifest = %q", copied)
	}
	afterLoad, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterLoad, legacy) {
		t.Fatalf("legacy Profile was rewritten: %s", afterLoad)
	}
}

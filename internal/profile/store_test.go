package profile_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestStoreCreatesAtomicHumanReadableUserOnlyProfileWithoutOverwrite(t *testing.T) {
	acsHome := t.TempDir()
	store := profile.NewStore(acsHome)
	original := profile.Profile{
		Version: profile.CurrentVersion,
		Name:    "backend-review",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{{
			Source:       "devin-config",
			RelativePath: "review",
		}},
	}
	path, err := store.Create(original)
	if err != nil {
		t.Fatalf("create Profile: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, fragment := range []string{"\n  \"name\": \"backend-review\"", "\n  \"skillReferences\": [", "\"source\": \"devin-config\"", "\"relativePath\": \"review\""} {
		if !strings.Contains(text, fragment) {
			t.Errorf("Profile JSON is not human-readable or is missing %q:\n%s", fragment, text)
		}
	}
	profileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if profileInfo.Mode().Perm() != 0o600 {
		t.Errorf("Profile permissions = %o, want 600", profileInfo.Mode().Perm())
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Errorf("Profile directory permissions = %o, want 700", directoryInfo.Mode().Perm())
	}

	replacement := original
	replacement.SkillReferences = nil
	if _, err := store.Create(replacement); !errors.Is(err, profile.ErrProfileExists) {
		t.Fatalf("duplicate create error = %v, want ErrProfileExists", err)
	}
	afterDuplicate, err := store.Load(original.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterDuplicate.SkillReferences) != 1 || afterDuplicate.SkillReferences[0] != original.SkillReferences[0] {
		t.Fatalf("duplicate create overwrote original Profile: %#v", afterDuplicate)
	}

	temporaryMatches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".profile-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaryMatches) != 0 {
		t.Fatalf("temporary Profile files remain after atomic publish: %v", temporaryMatches)
	}
}

func TestStoreRejectsInvalidNameOnLoad(t *testing.T) {
	acsHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(acsHome, "escape.json"), []byte(`{"version":1,"name":"escape","target":"devin","skillReferences":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(acsHome)

	if _, err := store.Load("../escape"); !errors.Is(err, profile.ErrInvalidProfileName) {
		t.Fatalf("invalid load error = %v, want ErrInvalidProfileName", err)
	}
}

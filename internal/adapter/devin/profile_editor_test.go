package devin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestStoredProfileEditorSeedsWithoutSourceResolution(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"lost"}]}`,
		`{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[{"source":"devin-config","relativePath":"lost"}]}}}`,
	} {
		home := t.TempDir()
		editor, err := NewProfileEditor(home)
		if err != nil {
			t.Fatal(err)
		}
		if editor.sandbox != nil || editor.binaryPath != "" {
			t.Fatal("stored selection assembly constructed runtime")
		}
		if entry := profileinspect.InspectBytes("old", []byte(raw)); entry.Status != "valid" {
			t.Fatal(entry)
		}
		profile, err := editor.categories.Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		draft, err := editor.categories.DraftFromProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		references, err := category.Selection(draft, editor.skillsCategory)
		want := []skills.SkillReference{{Source: "devin-config", RelativePath: "lost"}}
		if err != nil || !reflect.DeepEqual(references, want) {
			t.Fatalf("seed: %v %v", references, err)
		}
		discovery, err := editor.discoverProfileSkills(context.Background())
		if err != nil || len(discovery.Bundles) != 0 || len(discovery.UnavailableSources) != 0 {
			t.Fatalf("missing roots discovery: %v %v", discovery, err)
		}
		// A bundle directory without its manifest is a known absent choice.
		if err := os.MkdirAll(filepath.Join(home, ".config", "devin", "skills", "lost"), 0700); err != nil {
			t.Fatal(err)
		}
		discovery, err = editor.discoverProfileSkills(context.Background())
		if err != nil || len(discovery.Bundles) != 0 {
			t.Fatalf("missing manifest: %v %v", discovery, err)
		}
		retained, _ := category.Selection(draft, editor.skillsCategory)
		if !reflect.DeepEqual(retained, want) {
			t.Fatal("discovery altered selection")
		}
	}
}

func TestStoredProfileRepairPreservesHealthySourceWhenAnotherFails(t *testing.T) {
	home := t.TempDir()
	editor, err := NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".config", "devin", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		t.Fatal(err)
	}
	// An obstructing regular file gives a deterministic discovery failure even
	// when the test process has privileges that bypass chmod denial.
	if err := os.WriteFile(root, []byte("obstructed source"), 0600); err != nil {
		t.Fatal(err)
	}
	writeEditorSkill(t, home, filepath.Join(".agents", "skills", "review"))
	discovery, err := editor.discoverProfileSkills(context.Background())
	if err != nil || !discovery.UnavailableSources["devin-config"] || discovery.UnavailableSources["shared-agents"] || len(discovery.Bundles) != 1 || discovery.Bundles[0].Reference.Source != "shared-agents" {
		t.Fatalf("partial discovery: %v %v", discovery, err)
	}
	// Full launch discovery is deliberately still fail-closed on source errors.
	if _, err := editor.DiscoverGlobalSkillCatalog(context.Background()); err == nil {
		t.Fatal("repair broadened launch semantics")
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	writeEditorSkill(t, home, filepath.Join(".config", "devin", "skills", "review"))
	discovery, err = editor.discoverProfileSkills(context.Background())
	if err != nil || len(discovery.UnavailableSources) != 0 || len(discovery.Bundles) != 2 {
		t.Fatalf("repaired source: %v %v", discovery, err)
	}
	if discovery.Bundles[0].Reference == discovery.Bundles[1].Reference {
		t.Fatal("same display name rebound identity")
	}
}

func TestStoredProfileRepairActualSourcePermissionDenial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".config", "devin", "skills")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0700)
	if _, err := os.ReadDir(root); !os.IsPermission(err) {
		t.Fatalf("host did not establish the required actual source permission denial: %v", err)
	}
	t.Logf("uid=%d: source mode 0000 produced observed permission denial", os.Geteuid())
	writeEditorSkill(t, home, filepath.Join(".agents", "skills", "repair"))
	editor, err := NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	result, err := editor.discoverProfileSkills(context.Background())
	if err != nil || !result.UnavailableSources["devin-config"] || len(result.Bundles) != 1 {
		t.Fatalf("permission denial lost repair choices: %v %v", result, err)
	}
}

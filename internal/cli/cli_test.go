package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestCreateProfileSelectsSameNamedSkillBundlesIndependently(t *testing.T) {
	acsHome := t.TempDir()
	profiles := profile.NewStore(acsHome)
	catalog := staticCatalog{bundles: []skills.SkillBundle{
		{
			Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
			DisplayName: "review",
			SourceRoot:  "/global/devin/skills",
			Path:        "/global/devin/skills/review",
		},
		{
			Reference:   skills.SkillReference{Source: "shared-agents", RelativePath: "review"},
			DisplayName: "review",
			SourceRoot:  "/global/agents/skills",
			Path:        "/global/agents/skills/review",
		},
	}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     catalog,
		Profiles:    profiles,
		Input:       strings.NewReader("1,2\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "reviews"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	for _, sourceDetail := range []string{
		"review [devin-config] /global/devin/skills/review",
		"review [shared-agents] /global/agents/skills/review",
	} {
		if !strings.Contains(stdout.String(), sourceDetail) {
			t.Errorf("selector output does not identify source %q:\n%s", sourceDetail, stdout.String())
		}
	}

	saved, err := profiles.Load("reviews")
	if err != nil {
		t.Fatalf("load created Profile: %v", err)
	}
	want := profile.Profile{
		Version: 1,
		Name:    "reviews",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{
			{Source: "devin-config", RelativePath: "review"},
			{Source: "shared-agents", RelativePath: "review"},
		},
	}
	if !reflect.DeepEqual(saved, want) {
		t.Fatalf("saved Profile = %#v, want %#v", saved, want)
	}

	wantPath := filepath.Join(acsHome, "profiles", "reviews.json")
	if !strings.Contains(stdout.String(), wantPath) {
		t.Errorf("success output does not report Profile path %q:\n%s", wantPath, stdout.String())
	}
}

func TestCreateProfileEscapesCatalogControlCharactersInSelector(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog: staticCatalog{bundles: []skills.SkillBundle{{
			Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review\nforged"},
			DisplayName: "review\nforged",
			Path:        "/global/review\x1b[31m",
		}}},
		Profiles:    profiles,
		Input:       strings.NewReader("1\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "escaped"}); exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if strings.ContainsAny(stdout.String(), "\x1b") || strings.Contains(stdout.String(), "review\nforged") {
		t.Fatalf("selector contains raw terminal control characters: %q", stdout.String())
	}
	for _, escaped := range []string{`review\nforged`, `review\x1b[31m`} {
		if !strings.Contains(stdout.String(), escaped) {
			t.Errorf("selector does not visibly escape %q: %q", escaped, stdout.String())
		}
	}
}

func TestCreateProfileSavesEmptySelectionOnlyAfterExplicitConfirmation(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{},
		Profiles:    profiles,
		Input:       strings.NewReader("\ny\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "empty"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Create an empty Profile? [y/N]") {
		t.Fatalf("empty selection was not explicitly confirmed:\n%s", stdout.String())
	}
	saved, err := profiles.Load("empty")
	if err != nil {
		t.Fatalf("load empty Profile: %v", err)
	}
	if saved.SkillReferences == nil || len(saved.SkillReferences) != 0 {
		t.Fatalf("saved Skill References = %#v, want a deliberate empty selection", saved.SkillReferences)
	}
}

func TestCreateProfileDoesNotSaveDeclinedEmptySelection(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{},
		Profiles:    profiles,
		Input:       strings.NewReader("\nn\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "declined"})
	if exitCode == 0 {
		t.Fatal("declined empty Profile was saved")
	}
	if !strings.Contains(stderr.String(), "not confirmed") {
		t.Fatalf("declined empty Profile error is unclear: %s", stderr.String())
	}
	if _, err := profiles.Load("declined"); !os.IsNotExist(err) {
		t.Fatalf("declined empty Profile exists: %v", err)
	}
}

func TestCreateProfileRejectsInvalidNameBeforeDiscoveryOrWrite(t *testing.T) {
	acsHome := t.TempDir()
	profiles := profile.NewStore(acsHome)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{err: errors.New("catalog should not be called")},
		Profiles:    profiles,
		Input:       strings.NewReader(""),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "../escape"})
	if exitCode == 0 {
		t.Fatal("invalid Profile name was accepted")
	}
	if !strings.Contains(stderr.String(), "invalid Profile name") {
		t.Fatalf("invalid-name error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(acsHome, "escape.json")); !os.IsNotExist(err) {
		t.Fatal("invalid Profile name escaped the Profile directory")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid name started interactive discovery:\n%s", stdout.String())
	}
}

func TestCreateProfileRejectsDuplicateNameWithoutOverwriting(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	catalog := staticCatalog{bundles: []skills.SkillBundle{
		{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "first"}, DisplayName: "first", Path: "/devin/first"},
		{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "second"}, DisplayName: "second", Path: "/agents/second"},
	}}
	run := func(input string) (int, string) {
		t.Helper()
		var stderr bytes.Buffer
		application := cli.App{
			Catalog:     catalog,
			Profiles:    profiles,
			Input:       strings.NewReader(input),
			Output:      &bytes.Buffer{},
			ErrorOutput: &stderr,
		}
		return application.Run(context.Background(), []string{"devin", "create-profile", "--name", "unique"}), stderr.String()
	}

	if exitCode, stderr := run("1\n"); exitCode != 0 {
		t.Fatalf("initial create failed with exit %d: %s", exitCode, stderr)
	}
	if exitCode, stderr := run("2\n"); exitCode == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate create exit = %d, stderr = %q", exitCode, stderr)
	}
	saved, err := profiles.Load("unique")
	if err != nil {
		t.Fatal(err)
	}
	want := skills.SkillReference{Source: "devin-config", RelativePath: "first"}
	if len(saved.SkillReferences) != 1 || saved.SkillReferences[0] != want {
		t.Fatalf("duplicate create overwrote original Profile: %#v", saved)
	}
}

type staticCatalog struct {
	bundles []skills.SkillBundle
	err     error
}

func (catalog staticCatalog) DiscoverGlobalSkillCatalog(context.Context) ([]skills.SkillBundle, error) {
	return catalog.bundles, catalog.err
}

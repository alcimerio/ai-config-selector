package profile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestStoreDoesNotWriteWhenCreateContextIsCancelled(t *testing.T) {
	acsHome := t.TempDir()
	store := newDevinStore(t, acsHome)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.CreateContext(ctx, devin.NewSkillsProfile("cancelled", nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateContext error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(acsHome, "profiles", "cancelled.json")); !os.IsNotExist(err) {
		t.Fatalf("cancelled CreateContext wrote a Profile: %v", err)
	}
}

func TestStoreCreatesAtomicHumanReadableUserOnlyProfileWithoutOverwrite(t *testing.T) {
	acsHome := t.TempDir()
	store := newDevinStore(t, acsHome)
	original := devin.NewSkillsProfile("backend-review", []skills.SkillReference{
		{Source: "shared-agents", RelativePath: "security"},
		{Source: "devin-config", RelativePath: "review"},
	})
	path, err := store.Create(original)
	if err != nil {
		t.Fatalf("create Profile: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, fragment := range []string{
		"\n  \"version\": 2",
		"\n  \"name\": \"backend-review\"",
		"\n  \"categories\": {",
		"\n    \"skills\": {",
		"\n      \"schemaVersion\": 1",
		"\n      \"selection\": [",
		"\"source\": \"devin-config\"",
		"\"relativePath\": \"review\"",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("Profile JSON is not human-readable or is missing %q:\n%s", fragment, text)
		}
	}
	if strings.Index(text, `"source": "devin-config"`) > strings.Index(text, `"source": "shared-agents"`) {
		t.Fatalf("Profile Skill References are not sorted by stable identity:\n%s", text)
	}
	if strings.Contains(text, "skillReferences") {
		t.Fatalf("version-2 Profile contains the version-1 field:\n%s", text)
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

	replacement := devin.NewSkillsProfile("backend-review", nil)
	if _, err := store.Create(replacement); !errors.Is(err, profile.ErrProfileExists) {
		t.Fatalf("duplicate create error = %v, want ErrProfileExists", err)
	}
	afterDuplicate, err := store.Load(original.Name)
	if err != nil {
		t.Fatal(err)
	}
	references, err := devin.SkillReferences(afterDuplicate)
	if err != nil {
		t.Fatal(err)
	}
	wantReferences := []skills.SkillReference{
		{Source: "devin-config", RelativePath: "review"},
		{Source: "shared-agents", RelativePath: "security"},
	}
	if !reflect.DeepEqual(references, wantReferences) {
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
	store := newDevinStore(t, acsHome)

	if _, err := store.Load("../escape"); !errors.Is(err, profile.ErrInvalidProfileName) {
		t.Fatalf("invalid load error = %v, want ErrInvalidProfileName", err)
	}
}

func TestStoreLoadsVersionOneProfileAsVersionTwoWithoutRewritingIt(t *testing.T) {
	acsHome := t.TempDir()
	profilesDir := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte("{\n  \"version\": 1,\n  \"name\": \"legacy\",\n  \"target\": \"devin\",\n  \"skillReferences\": [\n    {\"source\": \"shared-agents\", \"relativePath\": \"security\"},\n    {\"source\": \"devin-config\", \"relativePath\": \"review\"}\n  ]\n}\n")
	path := filepath.Join(profilesDir, "legacy.json")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := newDevinStore(t, acsHome).Load("legacy")
	if err != nil {
		t.Fatalf("load version-1 Profile: %v", err)
	}
	if loaded.Version != profile.CurrentVersion {
		t.Fatalf("normalized Profile version = %d, want %d", loaded.Version, profile.CurrentVersion)
	}
	references, err := devin.SkillReferences(loaded)
	if err != nil {
		t.Fatal(err)
	}
	wantReferences := []skills.SkillReference{
		{Source: "devin-config", RelativePath: "review"},
		{Source: "shared-agents", RelativePath: "security"},
	}
	if !reflect.DeepEqual(references, wantReferences) {
		t.Fatalf("normalized Skill References = %#v, want %#v", references, wantReferences)
	}
	afterLoad, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterLoad, legacy) {
		t.Fatalf("loading rewrote the version-1 Profile:\n%s", afterLoad)
	}
}

func TestStoreDefaultsAProfileWithoutSkillsToAnEmptySelection(t *testing.T) {
	acsHome := t.TempDir()
	profilesDir := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(profilesDir, "before-skills.json"),
		[]byte(`{"version":2,"name":"before-skills","target":"devin","categories":{}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	loaded, err := newDevinStore(t, acsHome).Load("before-skills")
	if err != nil {
		t.Fatalf("load Profile without Skills category: %v", err)
	}
	payload, exists := loaded.Categories["skills"]
	if !exists {
		t.Fatal("normalized Profile does not contain the empty Skills category")
	}
	if payload.SchemaVersion != 1 || string(payload.Selection) != "[]" {
		t.Fatalf("empty Skills payload = %#v, want schema version 1 and []", payload)
	}
}

func TestStoreRejectsInvalidVersionTwoSavedIntent(t *testing.T) {
	tests := []struct {
		name          string
		contents      string
		wantErrorText string
	}{
		{
			name:          "unknown-category",
			contents:      `{"version":2,"name":"unknown-category","target":"devin","categories":{"agents":{"schemaVersion":1,"selection":[]}}}`,
			wantErrorText: `unknown Profile category "agents"`,
		},
		{
			name:          "unsupported-category-schema",
			contents:      `{"version":2,"name":"unsupported-category-schema","target":"devin","categories":{"skills":{"schemaVersion":2,"selection":[]}}}`,
			wantErrorText: "skills category uses unsupported schema version 2",
		},
		{
			name:          "malformed-selection-shape",
			contents:      `{"version":2,"name":"malformed-selection-shape","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":{}}}}`,
			wantErrorText: "decode skills category selection",
		},
		{
			name:          "malformed-reference",
			contents:      `{"version":2,"name":"malformed-reference","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[{"source":"devin-config"}]}}}`,
			wantErrorText: "invalid Skill Reference",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertProfileLoadError(t, test.name, test.contents, test.wantErrorText)
		})
	}
}

func TestStoreRejectsInvalidVersionOneSavedIntent(t *testing.T) {
	tests := []struct {
		name          string
		contents      string
		wantErrorText string
	}{
		{
			name:          "missing-selection",
			contents:      `{"version":1,"name":"missing-selection","target":"devin"}`,
			wantErrorText: "decode version-1 skillReferences",
		},
		{
			name:          "null-selection",
			contents:      `{"version":1,"name":"null-selection","target":"devin","skillReferences":null}`,
			wantErrorText: "expected an array, got null",
		},
		{
			name:          "malformed-reference",
			contents:      `{"version":1,"name":"malformed-reference","target":"devin","skillReferences":[{"source":"devin-config"}]}`,
			wantErrorText: "invalid Skill Reference",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertProfileLoadError(t, test.name, test.contents, test.wantErrorText)
		})
	}
}

func assertProfileLoadError(t *testing.T, name, contents, wantErrorText string) {
	t.Helper()
	acsHome := t.TempDir()
	profilesDir := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profilesDir, name+".json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newDevinStore(t, acsHome).Load(name)
	if err == nil || !strings.Contains(err.Error(), wantErrorText) {
		t.Fatalf("load error = %v, want text %q", err, wantErrorText)
	}
}

func newDevinStore(t *testing.T, acsHome string) *profile.Store {
	t.Helper()
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return profile.NewStore(acsHome, adapter.Categories())
}

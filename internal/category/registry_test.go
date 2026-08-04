package category_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type textSelection struct {
	Values []string `json:"values"`
}

func TestProfileStoreUsesRegistryDefaultsWithoutKnowingCategoryTypes(t *testing.T) {
	texts := mustBind(t, category.Definition[textSelection, textResolved, textContribution]{
		ID:            "texts",
		SchemaVersion: 3,
		Empty:         func() textSelection { return textSelection{Values: []string{}} },
		Resolve: func(context.Context, textSelection) (textResolved, error) {
			return textResolved{}, nil
		},
		Contribute: func(textResolved) (textContribution, error) { return textContribution{}, nil },
		Count:      func(selection textSelection) int { return len(selection.Values) },
	})
	toggle := mustBind(t, category.Definition[toggleSelection, toggleResolved, toggleContribution]{
		ID:            "toggle",
		SchemaVersion: 1,
		Empty:         func() toggleSelection { return false },
		Resolve: func(context.Context, toggleSelection) (toggleResolved, error) {
			return 0, nil
		},
		Contribute: func(toggleResolved) (toggleContribution, error) { return toggleContribution{}, nil },
		Count:      func(toggleSelection) int { return 0 },
	})
	registry, err := category.NewRegistry("devin", texts.Registration(), toggle.Registration())
	if err != nil {
		t.Fatal(err)
	}
	acsHome := t.TempDir()
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(profilesDirectory, "older.json"),
		[]byte(`{"version":2,"name":"older","target":"devin","categories":{"texts":{"schemaVersion":3,"selection":{"values":["alpha"]}}}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	loaded, err := profile.NewStore(acsHome, registry).Load("older")
	if err != nil {
		t.Fatalf("load Profile: %v", err)
	}
	togglePayload, exists := loaded.Categories["toggle"]
	if !exists {
		t.Fatal("Registry did not add the empty toggle category")
	}
	if togglePayload.SchemaVersion != 1 || string(togglePayload.Selection) != "false" {
		t.Fatalf("empty toggle payload = %#v, want schema 1 and false", togglePayload)
	}
}

func TestProfileStoreUsesRegisteredLegacyDecoderWithoutRewritingSource(t *testing.T) {
	texts := mustBind(t, category.Definition[textSelection, textResolved, textContribution]{
		ID:            "texts",
		SchemaVersion: 3,
		Empty:         func() textSelection { return textSelection{Values: []string{}} },
		Resolve: func(context.Context, textSelection) (textResolved, error) {
			return textResolved{}, nil
		},
		Contribute: func(textResolved) (textContribution, error) { return textContribution{}, nil },
		Count:      func(selection textSelection) int { return len(selection.Values) },
	})
	registry, err := category.NewRegistryWithLegacy(
		"devin",
		[]category.Registration{texts.Registration()},
		category.LegacyDecoder{
			Version: 1,
			Decode: func(contents []byte) (profile.Profile, error) {
				var legacy struct {
					Version int           `json:"version"`
					Name    string        `json:"name"`
					Target  string        `json:"target"`
					Texts   textSelection `json:"texts"`
				}
				if err := json.Unmarshal(contents, &legacy); err != nil {
					return profile.Profile{}, err
				}
				selection, err := json.Marshal(legacy.Texts)
				if err != nil {
					return profile.Profile{}, err
				}
				return profile.Profile{
					Version: profile.CurrentVersion,
					Name:    legacy.Name,
					Target:  legacy.Target,
					Categories: map[string]profile.CategoryPayload{
						"texts": {SchemaVersion: 3, Selection: selection},
					},
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	acsHome := t.TempDir()
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"version":1,"name":"legacy","target":"devin","texts":{"values":["alpha"]}}`)
	path := filepath.Join(profilesDirectory, "legacy.json")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := profile.NewStore(acsHome, registry).Load("legacy")
	if err != nil {
		t.Fatalf("load legacy Profile: %v", err)
	}
	if loaded.Version != profile.CurrentVersion || string(loaded.Categories["texts"].Selection) != `{"values":["alpha"]}` {
		t.Fatalf("normalized legacy Profile = %#v", loaded)
	}
	afterLoad, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterLoad, legacy) {
		t.Fatalf("legacy Profile was rewritten: %s", afterLoad)
	}
}

type textResolved struct {
	Joined string
}

type textContribution struct{}

func (textContribution) Plan(context.Context, string, *launch.Plan) error {
	return nil
}
func (textContribution) Materialize(string) error { return nil }
func (textContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

type toggleSelection bool
type toggleResolved int
type toggleContribution struct{}

func (toggleContribution) Plan(context.Context, string, *launch.Plan) error {
	return nil
}
func (toggleContribution) Materialize(string) error { return nil }
func (toggleContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func TestRegistryBuildsProfileFromTypedDraftAndIncludesEmptyCategories(t *testing.T) {
	texts := mustBind(t, category.Definition[textSelection, textResolved, textContribution]{
		ID:            "texts",
		SchemaVersion: 3,
		Empty:         func() textSelection { return textSelection{Values: []string{}} },
		Resolve: func(context.Context, textSelection) (textResolved, error) {
			return textResolved{}, nil
		},
		Contribute: func(textResolved) (textContribution, error) { return textContribution{}, nil },
		Count:      func(selection textSelection) int { return len(selection.Values) },
	})
	toggle := mustBind(t, category.Definition[toggleSelection, toggleResolved, toggleContribution]{
		ID:            "toggle",
		SchemaVersion: 1,
		Empty:         func() toggleSelection { return false },
		Resolve: func(context.Context, toggleSelection) (toggleResolved, error) {
			return 0, nil
		},
		Contribute: func(toggleResolved) (toggleContribution, error) { return toggleContribution{}, nil },
		Count: func(selection toggleSelection) int {
			if selection {
				return 1
			}
			return 0
		},
	})
	registry, err := category.NewRegistry("devin", texts.Registration(), toggle.Registration())
	if err != nil {
		t.Fatalf("create Registry: %v", err)
	}

	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, texts, textSelection{Values: []string{"alpha", "beta"}}); err != nil {
		t.Fatalf("set typed selection: %v", err)
	}
	selectedTexts, err := category.Selection(draft, texts)
	if err != nil || !reflect.DeepEqual(selectedTexts.Values, []string{"alpha", "beta"}) {
		t.Fatalf("typed selection = %#v, error = %v", selectedTexts, err)
	}
	candidate, err := registry.NewProfile("typed", draft)
	if err != nil {
		t.Fatalf("build Profile: %v", err)
	}

	if candidate.Version != 2 || candidate.Name != "typed" || candidate.Target != "devin" {
		t.Fatalf("Profile envelope = %#v", candidate)
	}
	wantPayloads := map[string]struct {
		schemaVersion int
		selection     string
	}{
		"texts":  {schemaVersion: 3, selection: `{"values":["alpha","beta"]}`},
		"toggle": {schemaVersion: 1, selection: `false`},
	}
	if len(candidate.Categories) != len(wantPayloads) {
		t.Fatalf("category count = %d, want %d", len(candidate.Categories), len(wantPayloads))
	}
	for id, want := range wantPayloads {
		payload, exists := candidate.Categories[id]
		if !exists {
			t.Errorf("Profile is missing category %q", id)
			continue
		}
		if payload.SchemaVersion != want.schemaVersion || string(payload.Selection) != want.selection {
			t.Errorf("category %q payload = %#v, want schema %d selection %s", id, payload, want.schemaVersion, want.selection)
		}
	}

	summaries := draft.Summaries()
	wantSummaries := []category.Summary{{ID: "texts", Count: 2}, {ID: "toggle", Count: 0}}
	if !reflect.DeepEqual(summaries, wantSummaries) {
		t.Fatalf("Draft summaries = %#v, want %#v", summaries, wantSummaries)
	}
}

type numberedSelection struct {
	Value int `json:"value"`
}

type numberedResolved string

type namedSelection []string
type namedResolved struct {
	Count int
}

type recordingContribution struct {
	id         string
	operations *[]string
}

type pointerContribution struct{}

func (*pointerContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (*pointerContribution) Materialize(string) error                         { return nil }
func (*pointerContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func TestRegistryRejectsATypedNilLaunchContribution(t *testing.T) {
	binding := mustBind(t, category.Definition[bool, bool, *pointerContribution]{
		ID:            "pointer",
		SchemaVersion: 1,
		Empty:         func() bool { return false },
		Resolve:       func(_ context.Context, selected bool) (bool, error) { return selected, nil },
		Contribute:    func(bool) (*pointerContribution, error) { return nil, nil },
		Count:         func(bool) int { return 0 },
	})
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := registry.NewProfile("typed-nil", registry.NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "contribution is nil") {
		t.Fatalf("typed-nil contribution error = %v", err)
	}
}

func TestRegistryRejectsInvalidAssembly(t *testing.T) {
	validDefinition := category.Definition[numberedSelection, numberedResolved, recordingContribution]{
		ID:            "numbered",
		SchemaVersion: 1,
		Empty:         func() numberedSelection { return numberedSelection{} },
		Resolve:       func(context.Context, numberedSelection) (numberedResolved, error) { return "", nil },
		Contribute: func(numberedResolved) (recordingContribution, error) {
			return recordingContribution{id: "numbered", operations: new([]string)}, nil
		},
		Count: func(numberedSelection) int { return 0 },
	}

	for name, mutate := range map[string]func(*category.Definition[numberedSelection, numberedResolved, recordingContribution]){
		"invalid ID": func(definition *category.Definition[numberedSelection, numberedResolved, recordingContribution]) {
			definition.ID = "Not Stable"
		},
		"invalid schema": func(definition *category.Definition[numberedSelection, numberedResolved, recordingContribution]) {
			definition.SchemaVersion = 0
		},
		"incomplete entry": func(definition *category.Definition[numberedSelection, numberedResolved, recordingContribution]) {
			definition.Resolve = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			definition := validDefinition
			mutate(&definition)
			if _, err := category.Bind(definition); err == nil {
				t.Fatal("Bind accepted invalid category definition")
			}
		})
	}

	binding := mustBind(t, validDefinition)
	if _, err := category.NewRegistry("devin", binding.Registration(), binding.Registration()); err == nil || !strings.Contains(err.Error(), "duplicate category ID") {
		t.Fatalf("duplicate assembly error = %v", err)
	}
	if _, err := category.NewRegistry("devin", category.Registration{}); err == nil || !strings.Contains(err.Error(), "invalid registration") {
		t.Fatalf("incomplete assembly error = %v", err)
	}
	if _, err := category.NewRegistryWithLegacy("devin", []category.Registration{binding.Registration()}, category.LegacyDecoder{
		Version: profile.CurrentVersion + 1,
		Decode:  func([]byte) (profile.Profile, error) { return profile.Profile{}, nil },
	}); err == nil || !strings.Contains(err.Error(), "invalid legacy Profile decoder") {
		t.Fatalf("future legacy-decoder assembly error = %v", err)
	}

}

func (contribution recordingContribution) Plan(_ context.Context, _ string, _ *launch.Plan) error {
	*contribution.operations = append(*contribution.operations, "plan:"+contribution.id)
	return nil
}
func (contribution recordingContribution) Materialize(string) error {
	*contribution.operations = append(*contribution.operations, "materialize:"+contribution.id)
	return nil
}
func (contribution recordingContribution) Verify(context.Context, launch.VerificationContext) error {
	*contribution.operations = append(*contribution.operations, "verify:"+contribution.id)
	return nil
}

func TestRegistryResolvesTypedSelectionsAndRunsContributionsInOrder(t *testing.T) {
	var operations []string
	numbered := mustBind(t, category.Definition[numberedSelection, numberedResolved, recordingContribution]{
		ID:            "numbered",
		SchemaVersion: 1,
		Empty:         func() numberedSelection { return numberedSelection{} },
		Resolve: func(_ context.Context, selection numberedSelection) (numberedResolved, error) {
			return numberedResolved(strconv.Itoa(selection.Value)), nil
		},
		Contribute: func(resolved numberedResolved) (recordingContribution, error) {
			return recordingContribution{id: "numbered-" + string(resolved), operations: &operations}, nil
		},
		Count: func(numberedSelection) int { return 1 },
	})
	named := mustBind(t, category.Definition[namedSelection, namedResolved, recordingContribution]{
		ID:            "named",
		SchemaVersion: 1,
		Empty:         func() namedSelection { return namedSelection{} },
		Resolve: func(_ context.Context, selection namedSelection) (namedResolved, error) {
			return namedResolved{Count: len(selection)}, nil
		},
		Contribute: func(namedResolved) (recordingContribution, error) {
			return recordingContribution{id: "named", operations: &operations}, nil
		},
		Count: func(selection namedSelection) int { return len(selection) },
	})
	registry, err := category.NewRegistry("devin", numbered.Registration(), named.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, numbered, numberedSelection{Value: 7}); err != nil {
		t.Fatal(err)
	}
	if err := category.SetSelection(&draft, named, namedSelection{"alpha", "beta"}); err != nil {
		t.Fatal(err)
	}
	candidate, err := registry.NewProfile("ordered", draft)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := registry.Resolve(context.Background(), candidate)
	if err != nil {
		t.Fatalf("resolve Profile: %v", err)
	}
	if _, err := resolved.Plan(context.Background(), "/project"); err != nil {
		t.Fatalf("plan Profile: %v", err)
	}
	if err := resolved.Materialize("/session/home"); err != nil {
		t.Fatalf("materialize Profile: %v", err)
	}
	if err := resolved.Verify(context.Background(), launch.VerificationContext{}); err != nil {
		t.Fatalf("verify Profile: %v", err)
	}

	want := []string{
		"plan:numbered-7", "plan:named",
		"materialize:numbered-7", "materialize:named",
		"verify:numbered-7", "verify:named",
	}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("contribution operations = %#v, want %#v", operations, want)
	}
}

func mustBind[S, R any, C launch.Contribution](t *testing.T, definition category.Definition[S, R, C]) category.Binding[S, R, C] {
	t.Helper()
	binding, err := category.Bind(definition)
	if err != nil {
		t.Fatalf("bind category %q: %v", definition.ID, err)
	}
	return binding
}

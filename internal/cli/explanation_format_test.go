package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

var captureExplanationFormat = flag.Bool("capture-explanation-format", false, "print explanation format golden candidates")
var writeExplanationFormatGoldens = flag.Bool("write-explanation-format-goldens", false, "write explanation format goldens")

func TestExplanationFormatGoldens(t *testing.T) {
	fixture := explanationFormatFixture(t)
	for _, test := range []struct {
		name   string
		args   []string
		recipe string
	}{
		{name: "sandbox", recipe: "shell", args: []string{"explain", "sandbox", "--profile", "format-profile"}},
		{name: "devin", recipe: "devin", args: []string{"explain", "devin", "--profile", "format-profile"}},
		{name: "codex", recipe: "codex", args: []string{"explain", "codex", "--profile", "format-profile"}},
		{name: "run", recipe: "command", args: []string{"explain", "run", "--profile", "format-profile", "--", "/usr/bin/true", "PRIVATE_ARGUMENT"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []struct {
				name string
				json bool
			}{
				{name: "human"},
				{name: "json", json: true},
			} {
				t.Run(format.name, func(t *testing.T) {
					args := append([]string(nil), test.args...)
					if format.json {
						args = append(args[:len(args)-len(literalArguments(args))], append([]string{"--json"}, args[len(args)-len(literalArguments(args)):]...)...)
					}
					got := fixture.run(t, args)
					if format.json {
						decoded := decodeFormat1(t, got)
						assertFormat1Contract(t, decoded, test.recipe)
					}
					if *captureExplanationFormat {
						t.Logf("%s/%s:\n%s", test.name, format.name, got)
						return
					}
					if *writeExplanationFormatGoldens {
						writeExplanationGolden(t, test.name+"."+format.name, got)
						return
					}
					golden := readExplanationGolden(t, test.name+"."+format.name)
					if got != golden {
						t.Errorf("%s %s output differs from its exact golden:\n%s", test.name, format.name, explanationGoldenDiff(golden, got))
					}
				})
			}
		})
	}
}

func TestExplanationFormatRejectsUnknownAndMistypedJSONMembers(t *testing.T) {
	output := explanationFormatFixture(t).run(t, []string{"explain", "sandbox", "--profile", "format-profile", "--json"})
	decodeFormat1(t, output)
	for _, mutation := range []struct {
		name  string
		apply func(*map[string]any)
	}{
		{name: "unknown top-level", apply: func(document *map[string]any) { (*document)["unknown"] = true }},
		{name: "mistyped formatVersion", apply: func(document *map[string]any) { (*document)["formatVersion"] = "1" }},
		{name: "mistyped checks", apply: func(document *map[string]any) { (*document)["checks"] = map[string]any{} }},
		{name: "unknown nested value", apply: func(document *map[string]any) {
			firstFormatFact(t, *document)["value"].(map[string]any)["unknown"] = true
		}},
		{name: "mistyped nested value", apply: func(document *map[string]any) {
			firstFormatFact(t, *document)["value"].(map[string]any)["access"] = true
		}},
		{name: "mistyped diagnostic", apply: func(document *map[string]any) { (*document)["diagnostic"] = []any{} }},
	} {
		t.Run(mutation.name, func(t *testing.T) { assertStrictFormatRejected(t, mutateFormatJSON(t, output, mutation.apply)) })
	}
}

func TestExplanationFormatEscapesTerminalControlsAndRejectsInvalidUTF8(t *testing.T) {
	fixture := explanationFormatFixture(t)
	controlName := "format\x1b[31m-profile"
	assertRejectedPublicName(t, fixture.app, controlName)
	invalidName := string([]byte{'f', 0xff})
	assertRejectedPublicName(t, fixture.app, invalidName)
}

func assertRejectedPublicName(t *testing.T, fixture cli.App, name string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	fixture.Output, fixture.ErrorOutput = &stdout, &stderr
	if code := fixture.Run(context.Background(), []string{"explain", "sandbox", "--profile", name, "--json"}); code != 1 {
		t.Fatalf("invalid name code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), name) || strings.Contains(stderr.String(), name) || strings.Contains(stdout.String(), "\x1b") || strings.Contains(stderr.String(), "\x1b") {
		t.Fatalf("rejected name escaped through output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

type explanationFormatFixtureState struct {
	devin      *devin.Adapter
	devinStore cli.ProfileStore
	app        cli.App
}

func explanationFormatFixture(t *testing.T) explanationFormatFixtureState {
	t.Helper()
	home := t.TempDir()
	devinTarget, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	devinStore := profile.NewStore(filepath.Join(home, ".acs-devin"), devinTarget.Categories())
	devinProfile := withExecutableExplanationSelection(t, mustProfile(t, devinTarget, "format-profile"))
	if _, err := devinStore.Create(devinProfile); err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "codex", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	codexStore := profile.NewStore(filepath.Join(home, ".acs-codex"), codexTarget.Categories())
	codexProfile, err := codexTarget.Categories().NewProfileWithOverlay("format-profile", codexTarget.Categories().NewDraft(), profile.OverlayPayload{Version: 1, AuthRef: "private-format-auth"})
	if err != nil {
		t.Fatal(err)
	}
	codexProfile = withExecutableExplanationSelection(t, codexProfile)
	if _, err := codexStore.Create(codexProfile); err != nil {
		t.Fatal(err)
	}
	return explanationFormatFixtureState{devin: devinTarget, devinStore: devinStore, app: cli.App{Categories: devinTarget.Categories(), Profiles: devinStore, CodexTarget: codexTarget, CodexCategories: codexTarget.Categories(), CodexProfiles: codexStore, WorkingDirectory: home}}
}

func withExecutableExplanationSelection(t *testing.T, candidate profile.Profile) profile.Profile {
	t.Helper()
	selection, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{
		{ID: "fixed-tool", Reference: executableintent.Reference{Kind: string(executableintent.ReferenceFixedSearchName), Name: "sh"}},
		{ID: "workspace-tool", Reference: executableintent.Reference{Kind: string(executableintent.ReferenceWorkspaceRelative), Path: "bin/tool"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: commonprofile.ExecutablesCapabilityVersion, Selection: selection}
	return candidate
}

func mustProfile(t *testing.T, target *devin.Adapter, name string) profile.Profile {
	t.Helper()
	candidate, err := target.Categories().NewProfile(name, target.Categories().NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func (fixture explanationFormatFixtureState) run(t *testing.T, args []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := fixture.app
	app.Output, app.ErrorOutput = &stdout, &stderr
	if code := app.Run(context.Background(), args); code != 0 {
		t.Fatalf("%q code=%d stderr=%q", args, code, stderr.String())
	}
	if strings.Contains(stdout.String(), "private-format-auth") || strings.Contains(stdout.String(), fixture.app.WorkingDirectory) || strings.Contains(stdout.String(), "PRIVATE_ARGUMENT") {
		t.Fatalf("private fixture input escaped: %s", stdout.String())
	}
	return stdout.String()
}

func literalArguments(args []string) []string {
	for index, value := range args {
		if value == "--" {
			return args[index:]
		}
	}
	return nil
}

func readExplanationGolden(t *testing.T, name string) string {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "explanation-format", name+".golden"))
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes)
}

func writeExplanationGolden(t *testing.T, name, output string) {
	t.Helper()
	directory := filepath.Join("testdata", "explanation-format")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".golden"), []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
}
func explanationGoldenDiff(want, got string) string {
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	for index := 0; index < len(wantLines) && index < len(gotLines); index++ {
		if wantLines[index] != gotLines[index] {
			return fmt.Sprintf("first difference at line %d\n-want %q\n+got  %q", index+1, wantLines[index], gotLines[index])
		}
	}
	return fmt.Sprintf("line count differs: want %d, got %d", len(wantLines), len(gotLines))
}

type strictExplanation struct {
	FormatVersion int                       `json:"formatVersion"`
	Operation     string                    `json:"operation"`
	Profile       strictExplanationProfile  `json:"profile"`
	Intent        strictExplanationIntent   `json:"intent"`
	Plan          *strictExplanationPlan    `json:"plan"`
	Checks        []strictExplanationCheck  `json:"checks"`
	Limitations   []strictExplanationLimit  `json:"limitations"`
	Diagnostic    *strictExplanationProblem `json:"diagnostic"`
}
type strictExplanationProfile struct {
	Name          string `json:"name"`
	StoredVersion int    `json:"storedVersion"`
	Compatibility string `json:"compatibility"`
}
type strictExplanationIntent struct {
	Recipe  string  `json:"recipe"`
	Overlay *string `json:"overlay"`
}
type strictExplanationPlan struct {
	AuthorityManifestVersion int                     `json:"authorityManifestVersion"`
	AuthorityDigest          string                  `json:"authorityDigest"`
	Requested                []strictExplanationFact `json:"requested"`
	TargetAdded              []strictExplanationFact `json:"targetAdded"`
	Effective                []strictExplanationFact `json:"effective"`
	Unsupported              []strictExplanationFact `json:"unsupported"`
}
type strictExplanationFact struct {
	ID     string                  `json:"id"`
	Kind   string                  `json:"kind"`
	Value  strictExplanationValue  `json:"value"`
	Reason string                  `json:"reason"`
	Source strictExplanationSource `json:"source"`
}
type strictExplanationValue struct {
	Access           string                     `json:"access,omitempty"`
	Mode             string                     `json:"mode,omitempty"`
	LogicalLocation  string                     `json:"logicalLocation,omitempty"`
	LogicalReference string                     `json:"logicalReference,omitempty"`
	RequirementID    string                     `json:"requirementId,omitempty"`
	Identity         *strictExplanationIdentity `json:"identity,omitempty"`
	Names            []string                   `json:"names,omitempty"`
	Count            *int                       `json:"count,omitempty"`
}
type strictExplanationIdentity struct {
	Source       string `json:"source"`
	RelativePath string `json:"relativePath"`
}
type strictExplanationSource struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version int    `json:"version,omitempty"`
}
type strictExplanationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}
type strictExplanationLimit struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}
type strictExplanationProblem struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	NextStep string `json:"nextStep"`
}

func decodeFormat1(t *testing.T, input string) strictExplanation {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.DisallowUnknownFields()
	var decoded strictExplanation
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("format-1 strict decode: %v\n%s", err, input)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("format-1 JSON contains trailing data: %v", err)
	}
	return decoded
}

func mutateFormatJSON(t *testing.T, input string, apply func(*map[string]any)) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(input), &document); err != nil {
		t.Fatal(err)
	}
	apply(&document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func firstFormatFact(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	plan, ok := document["plan"].(map[string]any)
	if !ok {
		t.Fatal("format fixture lacks plan object")
	}
	requested, ok := plan["requested"].([]any)
	if !ok || len(requested) == 0 {
		t.Fatal("format fixture lacks requested fact")
	}
	for _, candidate := range requested {
		fact, ok := candidate.(map[string]any)
		if !ok {
			t.Fatal("format fixture requested fact is not an object")
		}
		value, ok := fact["value"].(map[string]any)
		if !ok {
			t.Fatal("format fixture requested fact lacks value object")
		}
		if _, exists := value["access"]; exists {
			return fact
		}
	}
	t.Fatal("format fixture lacks requested access anchor")
	return nil
}

func assertStrictFormatRejected(t *testing.T, input string) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.DisallowUnknownFields()
	var decoded strictExplanation
	if err := decoder.Decode(&decoded); err == nil {
		t.Fatalf("strict decoder accepted malformed format-1 JSON: %s", input)
	}
}

func assertFormat1Contract(t *testing.T, result strictExplanation, recipe string) {
	t.Helper()
	if result.FormatVersion != 1 || result.Operation != "explain" || result.Plan == nil || result.Diagnostic != nil {
		t.Fatalf("invalid format-1 envelope: %#v", result)
	}
	if result.Profile.Name != "format-profile" || result.Profile.StoredVersion != 3 || result.Profile.Compatibility != "current" || result.Intent.Recipe != recipe {
		t.Fatalf("unexpected public identity: %#v", result)
	}
	if !strings.HasPrefix(result.Plan.AuthorityDigest, "sha256:") || len(result.Plan.AuthorityDigest) != len("sha256:")+64 || result.Plan.AuthorityManifestVersion != 1 {
		t.Fatalf("invalid semantic authority metadata: %#v", result.Plan)
	}
	if result.Checks == nil || result.Limitations == nil || result.Plan.Requested == nil || result.Plan.TargetAdded == nil || result.Plan.Effective == nil || result.Plan.Unsupported == nil {
		t.Fatal("format-1 arrays must be present, including empty arrays")
	}
	if fact := formatFact(result.Plan.Requested, "common.workspace"); fact == nil || fact.Value.Access != "read-only" || fact.Reason != "stored_v3_intent" {
		t.Fatalf("workspace fact violates the format contract: %#v", fact)
	}
	if fact := formatFact(result.Plan.Requested, "execution.recipe"); fact == nil || fact.Value.Mode != recipe {
		t.Fatalf("recipe fact violates the format contract: %#v", fact)
	}
	if fact := formatFact(result.Plan.Effective, "runtime.network"); fact == nil || fact.Value.Mode != "local-ip-socket-bind-no-listen-coarse-outbound-ip-macos-dns" {
		t.Fatalf("network fact violates the format contract: %#v", fact)
	}
	if fact := formatFact(result.Plan.Requested, "common.executables.workspace-tool"); fact == nil || fact.Reason != "stored_v3_intent_covered_by_workspace_read" || fact.Value.LogicalReference != "bin/tool" {
		t.Fatalf("workspace-covered executable fact violates the format contract: %#v", fact)
	}
	if formatFact(result.Plan.Effective, "executable.workspace-tool") != nil {
		t.Fatal("workspace-covered executable was repeated as independent effective authority")
	}
	if formatFact(result.Plan.Requested, "common.executables.fixed-tool") == nil || formatFact(result.Plan.Effective, "executable.fixed-tool") == nil || formatFact(result.Plan.Effective, "runtime.executable-visibility") == nil || formatFact(result.Plan.Unsupported, "unsupported.exclusive-execution-filtering") == nil {
		t.Fatalf("executable requested/effective/intrinsic/non-exclusive facts are incomplete: %#v", result.Plan)
	}
	switch recipe {
	case "devin":
		if result.Intent.Overlay == nil || *result.Intent.Overlay != "devin" || formatFact(result.Plan.TargetAdded, "devin.project-skills") == nil {
			t.Fatalf("Devin target facts violate the format contract: %#v", result)
		}
	case "codex":
		if result.Intent.Overlay == nil || *result.Intent.Overlay != "codex" || formatFact(result.Plan.TargetAdded, "codex.sandbox") == nil || formatFact(result.Plan.Requested, "codex.authentication") == nil {
			t.Fatalf("Codex target facts violate the format contract: %#v", result)
		}
	case "command":
		if result.Intent.Overlay != nil || formatFact(result.Plan.Requested, "run.literal-argv") == nil || formatFact(result.Plan.TargetAdded, "run.command") == nil {
			t.Fatalf("literal-run facts violate the format contract: %#v", result)
		}
	case "shell":
		if result.Intent.Overlay != nil || formatFact(result.Plan.TargetAdded, "sandbox.shell") == nil {
			t.Fatalf("sandbox facts violate the format contract: %#v", result)
		}
	}
}

func formatFact(facts []strictExplanationFact, id string) *strictExplanationFact {
	for index := range facts {
		if facts[index].ID == id {
			return &facts[index]
		}
	}
	return nil
}

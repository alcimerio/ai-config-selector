package scripts

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
)

const exampleProfilesDirectory = "../examples/profiles"

// dryRunCreate runs the exact `acs profile create --file FILE --dry-run` path
// (internal/cli/profile_create.go createProfileFromDocument) with the same
// declarative codec cmd/acs/main.go wires (devin.NewProfileEditor). HOME and
// the ACS store are empty temporary directories, so an example cannot depend
// on host Skills, instructions, credentials or Profiles.
func dryRunCreate(t *testing.T, documentPath string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	app := cli.App{Categories: editor.Categories(), Profiles: profile.NewStore(filepath.Join(home, ".acs"), editor.Categories()), Output: &out, ErrorOutput: &errOut}
	code := app.Run(context.Background(), []string{"profile", "create", "--file", documentPath, "--dry-run"})
	return code, out.String(), errOut.String()
}

// canonicalFromPreview extracts the exact canonical JSON printed by dry-run.
func canonicalFromPreview(t *testing.T, preview string) string {
	t.Helper()
	start := strings.Index(preview, "{\n")
	end := strings.Index(preview, "\n}\n")
	if start < 0 || end < start {
		t.Fatalf("dry-run preview has no canonical JSON: %q", preview)
	}
	return preview[start : end+3]
}

func exampleProfileFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(exampleProfilesDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("examples/profiles contains no example Profiles")
	}
	return files
}

func TestExampleProfilesCreateThroughTheDeclarativeCodec(t *testing.T) {
	for _, file := range exampleProfileFiles(t) {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			absolute, err := filepath.Abs(file)
			if err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(absolute)
			if err != nil {
				t.Fatal(err)
			}
			code, preview, stderr := dryRunCreate(t, absolute)
			if code != 0 {
				t.Fatalf("acs profile create --file %s --dry-run exit=%d stderr=%q", filepath.Base(file), code, stderr)
			}
			// Examples are stored in canonical form so schema or default drift
			// shows up as a diff rather than a silently different saved Profile.
			if canonical := canonicalFromPreview(t, preview); canonical != string(contents) {
				t.Fatalf("%s is not canonical; replace it with the dry-run output:\n%s", filepath.Base(file), canonical)
			}

			var document struct {
				Name     string                     `json:"name"`
				Overlays map[string]json.RawMessage `json:"overlays"`
			}
			if err := json.Unmarshal(contents, &document); err != nil {
				t.Fatal(err)
			}
			if want := strings.TrimSuffix(filepath.Base(file), ".json"); document.Name != want {
				t.Fatalf("Profile name %q must match file name %q", document.Name, want)
			}
			// Examples must be portable and must not name a personal login.
			for _, forbidden := range []string{`"local-absolute"`, `"authRef"`, "/Users/", "/Volumes/"} {
				if strings.Contains(string(contents), forbidden) {
					t.Fatalf("example contains machine-specific content %s", forbidden)
				}
			}

			// A Profile with a target overlay must also be shareable through
			// the sanitized exchange format (export requires an overlay).
			if len(document.Overlays) == 0 {
				return
			}
			editor, err := devin.NewProfileEditor(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := editor.Categories().DecodeNamed(document.Name, contents)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := profileexchange.Export(candidate); err != nil {
				t.Fatalf("example cannot be exported for sharing: %v", err)
			}
		})
	}
}

// Prove the harness rejects invalid input instead of passing vacuously.
func TestExampleProfileHarnessRejectsInvalidDocuments(t *testing.T) {
	for name, document := range map[string]string{
		"unknown field":      `{"version":3,"name":"bad","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only","extra":true}}},"overlays":{}}`,
		"legacy envelope":    `{"version":2,"name":"bad","categories":{}}`,
		"reserved env name":  `{"version":3,"name":"bad","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"environment":{"version":1,"selection":{"entries":[{"id":"x","destination":"HOME","scope":"attached-process-tree","source":{"kind":"host-environment","name":"X"},"required":false,"classification":"non-secret"}]}}},"overlays":{}}`,
		"optional secret":    `{"version":3,"name":"bad","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"environment":{"version":1,"selection":{"entries":[{"id":"x","destination":"TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"X"},"required":false,"classification":"secret"}]}}},"overlays":{}}`,
		"escaping exclusion": `{"version":3,"name":"bad","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"up","type":"directory","reference":{"kind":"workspace-relative","path":"../outside"}}]}}},"overlays":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := dryRunCreate(t, path); code == 0 {
				t.Fatal("invalid document was accepted")
			}
		})
	}
}

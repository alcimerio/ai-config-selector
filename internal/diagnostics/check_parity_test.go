package diagnostics_test

import (
	"context"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckLegacyCommonAdmissionMatchesRegistry(t *testing.T) {
	for _, body := range []string{`{"version":1,"name":"example","target":"devin","skillReferences":[]}`, `{"version":2,"name":"example","target":"devin","categories":{}}`} {
		home := t.TempDir()
		editor, err := devin.NewProfileEditor(home)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(home, ".acs", "profiles")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := profile.NewStore(filepath.Join(home, ".acs"), editor.Categories()).Load("example")
		if err != nil {
			t.Fatal(err)
		}
		for target, overlay := range map[string]string{"devin": "devin", "sandbox": ""} {
			if _, err := editor.Categories().ResolveFor(context.Background(), loaded, overlay); err != nil {
				t.Fatal(err)
			}
			got := diagnostics.LaunchCheck(context.Background(), "example", target, func() (string, error) { return home, nil })
			if !got.Passed("profile.overlays") {
				t.Fatal(got)
			}
		}
	}
}

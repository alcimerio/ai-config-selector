package sandboxshell

import (
	"context"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"os"
	"path/filepath"
	"testing"
)

type shellSelection struct{ marker string }

func (selection shellSelection) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Selected Skills:"})
	return nil
}

func (selection shellSelection) Materialize(home string) error {
	bundle := filepath.Join(home, ".agents", "skills", "review")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte(selection.marker), 0o600); err != nil {
		return err
	}
	for _, startupFile := range []string{".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
		if err := os.WriteFile(filepath.Join(home, startupFile), []byte("print -r -- startup-file-loaded\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (shellSelection) Verify(context.Context, launch.VerificationContext) error { return nil }

func resolvedShellProfile(t *testing.T) category.ResolvedProfile {
	t.Helper()
	binding, err := category.Bind(category.Definition[string, string, shellSelection]{
		ID:            "skills",
		SchemaVersion: 1,
		Empty:         func() string { return "" },
		Resolve:       func(context.Context, string) (string, error) { return "selected", nil },
		Contribute:    func(resolved string) (shellSelection, error) { return shellSelection{marker: resolved}, nil },
		Count:         func(string) int { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, binding, "review"); err != nil {
		t.Fatal(err)
	}
	profile, err := registry.NewProfile("review", draft)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

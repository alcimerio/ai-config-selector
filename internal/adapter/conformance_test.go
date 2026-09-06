package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// TestMaintainedTargetsShareCommonSkillsAndWorkspaceContract is the common
// behavioral suite for the two maintained adapters. Target-specific lifecycle
// and credential proofs remain in their owning executor packages.
func TestMaintainedTargetsShareCommonSkillsAndWorkspaceContract(t *testing.T) {
	home := t.TempDir()
	selected := []skills.SkillReference{
		{Source: devin.GlobalSourceDevinConfig, RelativePath: "review"},
		{Source: devin.GlobalSourceSharedAgents, RelativePath: "delivery"},
	}
	writeBundle(t, home, ".config/devin/skills", "review", "selected review\n")
	writeBundle(t, home, ".agents/skills", "delivery", "selected delivery\n")
	writeBundle(t, home, ".agents/skills", "unselected", "must remain absent\n")

	workspace := t.TempDir()
	projectAgent := writeBundle(t, workspace, ".agents/skills", "project-agent", "project local\n")
	projectDevin := writeBundle(t, workspace, ".devin/skills", "project-devin", "project local\n")

	devinTarget, err := devin.New(devin.Config{BinaryPath: "/usr/bin/true", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "/usr/bin/true", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}

	for _, access := range []launch.WorkspaceAccess{launch.WorkspaceAccessReadOnly, launch.WorkspaceAccessReadWrite} {
		candidate := commonProfile(t, "shared", selected, access, map[string]profile.OverlayPayload{
			"devin": {Version: 1},
			"codex": {Version: 1, AuthRef: "work"},
		})
		for _, target := range []struct {
			name       string
			registry   *category.Registry
			plan       func(category.ResolvedProfile) (launch.Plan, error)
			projection func(skills.SkillReference) string
			project    []string
			absent     []string
		}{
			{
				name: "devin", registry: devinTarget.Categories(),
				plan: func(resolved category.ResolvedProfile) (launch.Plan, error) {
					return devinTarget.PlanLaunch(context.Background(), workspace, resolved)
				},
				projection: func(reference skills.SkillReference) string {
					root := ".agents/skills"
					if reference.Source == devin.GlobalSourceDevinConfig {
						root = ".config/devin/skills"
					}
					return filepath.Join(root, reference.RelativePath, "SKILL.md")
				},
				project: []string{projectAgent, projectDevin},
			},
			{
				name: "codex", registry: codexTarget.Categories(),
				plan: func(resolved category.ResolvedProfile) (launch.Plan, error) {
					return codexTarget.PlanLaunch(context.Background(), workspace, resolved, "")
				},
				projection: func(reference skills.SkillReference) string {
					return filepath.Join(".codex/skills", string(reference.Source), reference.RelativePath, "SKILL.md")
				},
				absent: []string{projectAgent, projectDevin},
			},
		} {
			t.Run(string(access)+"/"+target.name, func(t *testing.T) {
				resolved, err := target.registry.ResolveFor(context.Background(), candidate, target.name)
				if err != nil {
					t.Fatal(err)
				}
				if got := resolved.WorkspaceAccess(); got != access {
					t.Fatalf("resolved workspace access = %q, want %q", got, access)
				}
				plan, err := target.plan(resolved)
				if err != nil {
					t.Fatal(err)
				}
				text := renderPlan(plan)
				for _, reference := range selected {
					identity := string(reference.Source) + ":" + reference.RelativePath
					if !strings.Contains(text, identity) {
						t.Fatalf("plan omitted common identity %q:\n%s", identity, text)
					}
				}
				if !strings.Contains(text, "access="+string(access)) {
					t.Fatalf("plan omitted workspace intent %q:\n%s", access, text)
				}
				for _, path := range target.project {
					if !strings.Contains(text, path) {
						t.Fatalf("Devin plan omitted inherited project-local Skill %q", path)
					}
				}
				for _, path := range target.absent {
					if strings.Contains(text, path) {
						t.Fatalf("Codex plan represented project-local Skill as ACS-managed material: %q", path)
					}
				}

				sessionHome := t.TempDir()
				if err := resolved.Materialize(sessionHome); err != nil {
					t.Fatal(err)
				}
				for index, reference := range selected {
					common := filepath.Join(sessionHome, ".acs/common/v1/skills", string(reference.Source), reference.RelativePath, "SKILL.md")
					projection := filepath.Join(sessionHome, target.projection(reference))
					want := []string{"selected review\n", "selected delivery\n"}[index]
					assertContents(t, common, want)
					assertContents(t, projection, want)
				}
				assertAbsent(t, filepath.Join(sessionHome, ".acs/common/v1/skills/shared-agents/unselected/SKILL.md"))
				assertAbsent(t, filepath.Join(sessionHome, target.projection(skills.SkillReference{Source: devin.GlobalSourceSharedAgents, RelativePath: "unselected"})))
				assertAbsent(t, filepath.Join(sessionHome, ".agents/skills/project-agent/SKILL.md"))
				assertAbsent(t, filepath.Join(sessionHome, ".devin/skills/project-devin/SKILL.md"))
			})
		}
	}
}

func TestLegacyProfilesRemainDevinBoundUntilExplicitMigration(t *testing.T) {
	home := t.TempDir()
	writeBundle(t, home, ".config/devin/skills", "review", "legacy review\n")
	devinTarget, err := devin.New(devin.Config{BinaryPath: "/usr/bin/true", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "/usr/bin/true", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	versionOne := []byte(`{"version":1,"name":"legacy","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"review"}]}`)
	legacy, err := devinTarget.Categories().Decode(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codexTarget.Categories().Decode(versionOne); err == nil {
		t.Fatal("Codex accepted a version-1 Devin Profile")
	}
	resolved, err := devinTarget.Categories().ResolveFor(context.Background(), legacy, "devin")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SourceVersion() != 1 || resolved.WorkspaceAccess() != launch.WorkspaceAccessReadWrite {
		t.Fatalf("legacy authority = version %d, workspace %q", resolved.SourceVersion(), resolved.WorkspaceAccess())
	}
	legacyHome := t.TempDir()
	if err := resolved.Materialize(legacyHome); err != nil {
		t.Fatal(err)
	}
	assertContents(t, filepath.Join(legacyHome, ".config/devin/skills/review/SKILL.md"), "legacy review\n")
	assertAbsent(t, filepath.Join(legacyHome, ".acs/common/v1/skills/devin-config/review/SKILL.md"))

	draft, err := devinTarget.Categories().DraftFromProfile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	versionTwo, err := devinTarget.Categories().NewLegacyProfile("legacy-copy", draft)
	if err != nil {
		t.Fatal(err)
	}
	if versionTwo.Version != 2 || versionTwo.Target != "devin" {
		t.Fatalf("legacy rewrite changed binding: %#v", versionTwo)
	}
	if _, err := codexTarget.Categories().ResolveFor(context.Background(), versionTwo, "codex"); err == nil {
		t.Fatal("Codex silently reinterpreted a version-2 Devin Profile")
	}
	migrated, err := devinTarget.Categories().NewProfile("migrated", draft)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Version != 3 || migrated.Target != "" || len(migrated.Overlays) != 1 || migrated.Overlays["devin"].Version != 1 {
		t.Fatalf("explicit migration boundary = %#v", migrated)
	}
}

func TestUnsupportedSelectedOverlayAndCodexDryRunFailBeforeSideEffects(t *testing.T) {
	home := t.TempDir()
	globalAuth := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("global-auth-must-remain-opaque\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected := []skills.SkillReference{{Source: devin.GlobalSourceDevinConfig, RelativePath: "missing-on-purpose"}}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "/path/that/must/not/run", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	devinTarget, err := devin.New(devin.Config{BinaryPath: "/path/that/must/not/run", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := commonProfile(t, "unsupported", selected, launch.WorkspaceAccessReadOnly, map[string]profile.OverlayPayload{
		"codex": {Version: 2, AuthRef: "stored"},
	})
	if _, err := codexTarget.Categories().ResolveFor(context.Background(), unsupported, "codex"); err == nil || !strings.Contains(err.Error(), `selected target overlay "codex" uses unsupported version 2`) {
		t.Fatalf("unsupported selected Codex overlay result = %v", err)
	}
	valid := commonProfile(t, "valid", selected, launch.WorkspaceAccessReadOnly, map[string]profile.OverlayPayload{
		"codex":         {Version: 1, AuthRef: "stored"},
		"devin":         {Version: 1},
		"future-target": {Version: 99},
	})
	if _, err := codexTarget.Categories().ResolveFor(context.Background(), valid, "devin"); err == nil || !strings.Contains(err.Error(), `selected target overlay "devin" uses unsupported version 1`) {
		t.Fatalf("Codex Registry cross-target result = %v", err)
	}
	if _, err := devinTarget.Categories().ResolveFor(context.Background(), valid, "codex"); err == nil || !strings.Contains(err.Error(), `selected target overlay "codex" uses unsupported version 1`) {
		t.Fatalf("Devin Registry cross-target result = %v", err)
	}

	resolved, err := codexTarget.Categories().ResolveSyntaxFor(context.Background(), valid, "codex")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := codexTarget.PlanLaunch(context.Background(), t.TempDir(), resolved, "override")
	if err != nil {
		t.Fatal(err)
	}
	text := renderPlan(plan)
	if resolved.AuthRef() != "stored" || !strings.Contains(text, "reference=override") || strings.Contains(text, "global-auth-must-remain-opaque") {
		t.Fatalf("opaque stored/override contract failed: stored=%q plan=%s", resolved.AuthRef(), text)
	}
	assertContents(t, globalAuth, "global-auth-must-remain-opaque\n")
	assertAbsent(t, filepath.Join(home, ".acs", "sessions"))
}

func commonProfile(t *testing.T, name string, references []skills.SkillReference, access launch.WorkspaceAccess, overlays map[string]profile.OverlayPayload) profile.Profile {
	t.Helper()
	selection, err := json.Marshal(references)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := json.Marshal(map[string]launch.WorkspaceAccess{"access": access})
	if err != nil {
		t.Fatal(err)
	}
	return profile.Profile{Version: 3, SourceVersion: 3, Name: name,
		Common: map[string]profile.CommonPayload{
			"skills":    {Version: 1, Selection: selection},
			"workspace": {Version: 1, Selection: workspace},
		},
		Overlays: overlays,
	}
}

func writeBundle(t *testing.T, home, root, name, contents string) string {
	t.Helper()
	path := filepath.Join(home, filepath.FromSlash(root), name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func renderPlan(plan launch.Plan) string {
	var result strings.Builder
	for _, section := range plan.Sections {
		fmt.Fprintln(&result, section.Title)
		for _, item := range section.Items {
			fmt.Fprintln(&result, item.Label)
			for _, detail := range item.Details {
				fmt.Fprintf(&result, "%s=%s\n", detail.Label, detail.Value)
			}
		}
	}
	return result.String()
}

func assertContents(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != want {
		t.Fatalf("contents of %q = %q, %v; want %q", path, contents, err, want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unexpected material at %q: %v", path, err)
	}
}

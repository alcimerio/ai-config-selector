package extensionassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

// These are actual vendor definitions, not MCP servers renamed as extensions.
// Selecting the plugin's Skill component is an explicit assessment staging step:
// the production compiler does not install or activate the plugin package.
func TestExtensionDefinitionsUseExistingCompilerWithoutInventingActivation(t *testing.T) {
	for _, target := range []string{"codex", "devin"} {
		t.Run(target, func(t *testing.T) {
			ctx := context.Background()
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			workspace, host, session := filepath.Join(root, "work"), filepath.Join(root, "host"), filepath.Join(root, "sessions", "home")
			put := func(path string, data []byte, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			source := filepath.Join("testdata", target)
			// Copy complete genuine definition fixtures into the selected workspace.
			err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(source, path)
				if err != nil {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				put(filepath.Join(workspace, rel), data, 0600)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(workspace, "plugin", "plugin.json")
			if target == "devin" {
				manifestPath = filepath.Join(workspace, "plugin", ".devin-plugin", "plugin.json")
			}
			manifestData, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Name   string   `json:"name"`
				Schema string   `json:"$schema"`
				Skills []string `json:"skills"`
			}
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.Name != "acs-assessment" {
				t.Fatal("plugin identity lost")
			}
			if target == "codex" && manifest.Schema != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" {
				t.Fatal("wrong pinned plugin schema")
			}
			if target == "devin" && (len(manifest.Skills) != 1 || manifest.Skills[0] != "./skills/reviewer") {
				t.Fatal("wrong plugin component reference")
			}
			skill, err := os.ReadFile(filepath.Join(workspace, "plugin", "skills", "reviewer", "SKILL.md"))
			if err != nil {
				t.Fatal(err)
			}
			put(filepath.Join(host, ".agents", "skills", "reviewer", "SKILL.md"), skill, 0600)
			put(filepath.Join(workspace, "hooks", "witness"), []byte("#!/bin/sh\nexit 0\n"), 0700)
			put(filepath.Join(workspace, "input.json"), []byte("{\"marker\":\"ACS_INPUT_OK\"}\n"), 0600)
			binary := filepath.Join(root, "target")
			put(binary, []byte("not executed\n"), 0700)
			p := devin.NewSkillsProfile("definition-prototype", []skills.SkillReference{{Source: "shared-agents", RelativePath: "reviewer"}})
			role, hook := "agents/reviewer.md", "hooks.v1.json"
			if target == "codex" {
				role, hook = "agents/reviewer.toml", "hooks.json"
			}
			entries := []commonprofile.PathEntry{}
			for _, selected := range []struct {
				id, path string
				kind     pathintent.Type
			}{{"plugin", "plugin", pathintent.TypeDirectory}, {"role", role, pathintent.TypeFile}, {"hook-definition", hook, pathintent.TypeFile}, {"input", "input.json", pathintent.TypeFile}} {
				entries = append(entries, commonprofile.PathEntry{ID: selected.id, Access: pathintent.AccessReadOnly, Type: selected.kind, Reference: pathintent.Reference{Kind: string(pathintent.ReferenceWorkspaceRelative), Path: selected.path}})
			}
			paths, err := commonprofile.EncodePathSelection(commonprofile.PathSelection{Entries: entries})
			if err != nil {
				t.Fatal(err)
			}
			p.Common[commonprofile.PathsCapabilityID] = profile.CommonPayload{Version: commonprofile.PathsCapabilityVersion, Selection: paths}
			executables, err := commonprofile.EncodeExecutableSelection(commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{{ID: "witness", Reference: executableintent.Reference{Kind: string(executableintent.ReferenceWorkspaceRelative), Path: "hooks/witness"}}}})
			if err != nil {
				t.Fatal(err)
			}
			p.Common[commonprofile.ExecutablesCapabilityID] = profile.CommonPayload{Version: commonprofile.ExecutablesCapabilityVersion, Selection: executables}
			var registry *category.Registry
			if target == "codex" {
				adapter, err := codex.New(codex.Config{BinaryPath: binary, ExistingHomeDir: host})
				if err != nil {
					t.Fatal(err)
				}
				registry = adapter.Categories()
				p, err = codex.NewProfile(p.Name, "", p)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				adapter, err := devin.New(devin.Config{BinaryPath: binary, ExistingHomeDir: host})
				if err != nil {
					t.Fatal(err)
				}
				registry = adapter.Categories()
			}
			resolved, err := registry.ResolveFor(ctx, p, target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolved.Plan(ctx, workspace); err != nil {
				t.Fatal(err)
			}
			grants, err := resolved.ResolveFilesystemGrants(workspace, filepath.Join(root, "sessions"))
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != 4 {
				t.Fatalf("selected definition/input grants: %d", len(grants))
			}
			expectedGrants := map[string]bool{"plugin": true, "role": true, "hook-definition": true, "input": true}
			for _, g := range grants {
				if !expectedGrants[g.ID] || string(g.Access) != "read-only" {
					t.Fatalf("grant lost definition authority: %#v", g)
				}
				delete(expectedGrants, g.ID)
			}
			executableGrants, err := resolved.ResolveExecutableGrants(workspace, filepath.Join(root, "sessions"))
			if err != nil {
				t.Fatal(err)
			}
			if len(executableGrants) != 1 || executableGrants[0].ID != "witness" {
				t.Fatalf("helper grant: %#v", executableGrants)
			}
			if err := resolved.Materialize(session); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(session, ".agents", "skills", "reviewer", "SKILL.md")
			if target == "codex" {
				destination = filepath.Join(session, ".codex", "skills", "shared-agents", "reviewer", "SKILL.md")
			}
			actual, err := os.ReadFile(destination)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, skill) {
				t.Fatal("production Skill projection changed selected package component")
			}
			// Materialize's actual outputs contain only the supported component. Source
			// RO grants do not silently become vendor activation or discovery files.
			var files []string
			if err := filepath.WalkDir(session, func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if !d.IsDir() {
					files = append(files, path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			commonDestination := filepath.Join(session, ".acs", "common", "v1", "skills", "shared-agents", "reviewer", "SKILL.md")
			commonBytes, err := os.ReadFile(commonDestination)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(commonBytes, skill) {
				t.Fatal("common serialized component changed")
			}
			if len(files) != 2 || files[0] != commonDestination || files[1] != destination {
				t.Fatalf("unexpected extension activation artifacts: %v", files)
			}
			if target == "codex" {
				if mode, ok := resolved.Requirements().Semantics.ConfigurationMode("codex.plugins"); !ok || mode != "disabled" {
					t.Fatalf("plugin policy changed: %q %v", mode, ok)
				}
			}
			// Genuine hook command references the selected executable, but its event,
			// timeout and shell invocation have no hook contribution in the plan.
			hookData, err := os.ReadFile(filepath.Join(workspace, hook))
			if err != nil {
				t.Fatal(err)
			}
			var events map[string]json.RawMessage
			if target == "codex" {
				var outer struct {
					Hooks map[string]json.RawMessage `json:"hooks"`
				}
				if err := json.Unmarshal(hookData, &outer); err != nil {
					t.Fatal(err)
				}
				events = outer.Hooks
			} else {
				if err := json.Unmarshal(hookData, &events); err != nil {
					t.Fatal(err)
				}
			}
			var bindings []struct {
				Hooks []struct {
					Type, Command string
					Timeout       int
				}
			}
			if err := json.Unmarshal(events["SessionStart"], &bindings); err != nil {
				t.Fatal(err)
			}
			if len(bindings) != 1 || len(bindings[0].Hooks) != 1 {
				t.Fatal("invalid representative hook")
			}
			handler := bindings[0].Hooks[0]
			if handler.Type != "command" || handler.Command != "./hooks/witness" || handler.Timeout != 1 {
				t.Fatalf("wrong event contract: %#v", handler)
			}
			// Selected executable authority remains real: the same compiler refuses a
			// missing helper instead of treating the hook's command string as a grant.
			if err := os.Remove(filepath.Join(workspace, "hooks", "witness")); err != nil {
				t.Fatal(err)
			}
			if _, err := resolved.ResolveExecutableGrants(workspace, filepath.Join(root, "sessions")); err == nil {
				t.Fatal("missing selected hook executable accepted")
			}
			if err := os.Remove(filepath.Join(workspace, role)); err != nil {
				t.Fatal(err)
			}
			if _, err := resolved.ResolveFilesystemGrants(workspace, filepath.Join(root, "sessions")); err == nil {
				t.Fatal("missing selected role definition accepted")
			}
			// Role text is intentionally not interpreted as new process authority.
			roleData, err := os.ReadFile(filepath.Join(source, role))
			if err != nil {
				t.Fatal(err)
			}
			required := "allowed-tools:\n  - read"
			if target == "codex" {
				required = "[features]\nshell_tool = false"
			}
			if !strings.Contains(string(roleData), required) {
				t.Fatal("role restriction fixture lost")
			}
		})
	}
}

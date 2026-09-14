package launch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/mcpintent"
)

func TestMCPRecipeHelperSubprocess(t *testing.T) {
	if os.Getenv("ACS_MCP_HELPER_TEST_CHILD") != "1" {
		return
	}
	handled, err := RunMCPHelper([]string{"--acs-mcp-launch", os.Getenv("ACS_MCP_HELPER_HOME"), os.Getenv("ACS_MCP_HELPER_ID")})
	if !handled || err != nil {
		t.Fatalf("helper result handled=%v err=%v", handled, err)
	}
	t.Fatal("successful helper returned without replacing the process")
}

func TestMCPRecipeHelperExecutesSelectedReferencesAndRejectsMissingID(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	home := filepath.Join(root, "session-home")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(workspace, "selected input.json")
	if err := os.WriteFile(inputPath, []byte("selected"), 0o600); err != nil {
		t.Fatal(err)
	}
	withExecutableSearchPath(t, "/usr/bin", "/bin")
	executables, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "printf", ReferenceKind: ExecutableReferenceFixedSearchName, Name: "printf"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	const sentinel = "selected value with spaces"
	servers := []MCPServerIntent{{ID: "server", Transport: "stdio", ExecutableRef: "printf", Arguments: []MCPArgumentIntent{{Kind: "environment", Ref: "format"}, {Kind: "environment", Ref: "value"}, {Kind: "path", Ref: "input"}}}}
	environments := []EnvironmentIntent{
		{ID: "format", Destination: "MCP_ARG_FORMAT", Classification: environmentintent.ClassificationNonSecret, SourceKind: environmentintent.SourceHostEnvironment, SourceName: "MCP_ARG_FORMAT", Scope: environmentintent.ScopeAttachedProcessTree},
		{ID: "value", Destination: "MCP_ARG_VALUE", Classification: environmentintent.ClassificationNonSecret, SourceKind: environmentintent.SourceHostEnvironment, SourceName: "MCP_ARG_VALUE", Scope: environmentintent.ScopeAttachedProcessTree},
	}
	paths, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "input", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: filepath.Base(inputPath)}}, workspace, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := CompileMCPRecipes(servers, executables, paths, environments)
	if err != nil {
		t.Fatal(err)
	}
	recipeDir, err := WriteMCPRecipes(home, recipes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(recipeDir, "recipes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(sentinel)) {
		t.Fatal("runtime argv value was persisted in the recipe")
	}
	for _, test := range []struct {
		name       string
		id         string
		format     string
		value      string
		wantOutput string
		wantError  bool
	}{
		{name: "selected server", id: "server", format: "%s|%s", value: sentinel, wantOutput: sentinel + "|" + inputPath},
		{name: "unknown server", id: "missing", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestMCPRecipeHelperSubprocess$")
			command.Env = append(os.Environ(), "ACS_MCP_HELPER_TEST_CHILD=1", "ACS_MCP_HELPER_HOME="+home, "ACS_MCP_HELPER_ID="+test.id, "HOME="+home, "MCP_ARG_FORMAT="+test.format, "MCP_ARG_VALUE="+test.value)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if test.wantError {
				if err == nil || (!strings.Contains(stderr.String(), "MCP launcher recipe is invalid") && !strings.Contains(stdout.String(), "MCP launcher recipe is invalid")) {
					t.Fatalf("unknown server result err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				return
			}
			if err != nil || stdout.String() != test.wantOutput {
				t.Fatalf("selected helper result err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestMCPRecipeDecoderRequiresCanonicalBoundedRecipes(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	recipes := []MCPRecipe{{ID: "server", SessionHome: home, Arguments: []MCPRecipeArgument{}, EnvNames: []string{}, Disabled: []string{}}}
	encoded, err := json.Marshal(recipes)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if _, err := decodeMCPRecipes(encoded); err != nil {
		t.Fatalf("canonical recipe refused: %v", err)
	}
	for name, altered := range map[string][]byte{
		"case alias":       []byte(strings.Replace(string(encoded), `"id":"server"`, `"id":"server","ID":"other"`, 1)),
		"duplicate field":  []byte(strings.Replace(string(encoded), `"id":"server"`, `"id":"server","id":"other"`, 1)),
		"trailing content": append(append([]byte(nil), encoded...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMCPRecipes(altered); err == nil {
				t.Fatal("noncanonical recipe input was accepted")
			}
		})
	}

}

func TestMCPRecipeExpansionRespectsHelperReadBound(t *testing.T) {
	workspace := t.TempDir()
	sessions := filepath.Join(t.TempDir(), "sessions")
	input := filepath.Join(workspace, "input.json")
	if err := os.WriteFile(input, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "input", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "input.json"}}, workspace, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	withExecutableSearchPath(t, "/usr/bin", "/bin")
	executables, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "exe", ReferenceKind: ExecutableReferenceFixedSearchName, Name: "true"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	selection := mcpintent.Empty()
	intents := []MCPServerIntent{}
	for index := 0; index < 20; index++ {
		id := fmt.Sprintf("server-%d", index)
		server := mcpintent.Server{ID: id, Transport: "stdio", ExecutableRef: "exe", Arguments: []mcpintent.Argument{}, InputRefs: []string{"input"}, EnvironmentRefs: []string{}}
		intent := MCPServerIntent{ID: id, Transport: "stdio", ExecutableRef: "exe", InputRefs: []string{"input"}}
		for argument := 0; argument < 128; argument++ {
			server.Arguments = append(server.Arguments, mcpintent.Argument{Kind: "path", Ref: "input"})
			intent.Arguments = append(intent.Arguments, MCPArgumentIntent{Kind: "path", Ref: "input"})
		}
		selection.Servers = append(selection.Servers, server)
		intents = append(intents, intent)
	}
	logical, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcpintent.Decode(logical); err != nil {
		t.Fatalf("fixture is not admitted by the MCP schema: %v", err)
	}
	recipes, err := CompileMCPRecipes(intents, executables, paths, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(recipes)
	if err != nil || len(encoded) <= 1<<20 {
		t.Fatalf("fixture failed to exceed helper bound: bytes=%d err=%v", len(encoded), err)
	}
	if _, err := WriteMCPRecipes(t.TempDir(), recipes); err == nil {
		t.Fatalf("writer accepted %d-byte expanded recipe beyond helper read bound", len(encoded))
	}
}

func TestCompileMCPRecipesRetainsWorkspaceCoveredInputBindings(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	withExecutableSearchPath(t, "/usr/bin", "/bin")
	executables, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "server", ReferenceKind: ExecutableReferenceFixedSearchName, Name: "true"}}, workspace, sessions)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		parents bool
	}{
		{name: "workspace-covered"},
		{name: "parent-grant-covered", parents: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			grantWorkspace := workspace
			input := "settings.json"
			intents := []PathGrantIntent{}
			if test.parents {
				home := filepath.Join(root, "grant-home")
				grantWorkspace = filepath.Join(home, "workspace")
				if err := os.MkdirAll(filepath.Join(grantWorkspace, "config"), 0o700); err != nil {
					t.Fatal(err)
				}
				input = filepath.Join("config", input)
				intents = append(intents, PathGrantIntent{ID: "config-dir", Access: PathAccessReadOnly, Type: PathTypeDirectory, ReferenceKind: PathReferenceLocalAbsolute, Path: filepath.Join(grantWorkspace, "config")})
				if err := os.MkdirAll(filepath.Join(home, "outside-workspace"), 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
			}
			if err := os.WriteFile(filepath.Join(grantWorkspace, input), []byte("selected"), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.parents {
				intents = append(intents, PathGrantIntent{ID: "settings", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceLocalAbsolute, Path: filepath.Join(grantWorkspace, input)})
			} else {
				intents = append(intents, PathGrantIntent{ID: "settings", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: input})
			}
			grants, err := ResolveFilesystemGrants(intents, workspace, sessions, WorkspaceAccessReadOnly)
			if err != nil {
				t.Fatal(err)
			}
			var settings, parent FilesystemGrant
			for _, grant := range grants {
				if grant.ID == "settings" {
					settings = grant
				}
				if grant.ID == "config-dir" {
					parent = grant
				}
			}
			if settings.ID == "" || settings.path != filepath.Join(grantWorkspace, input) {
				t.Fatalf("selected input grant was lost: %#v", grants)
			}
			if test.parents && (!parent.effective || settings.effective) {
				t.Fatalf("expected effective parent and covered child grant: parent=%#v child=%#v", parent, settings)
			}
			recipes, err := CompileMCPRecipes([]MCPServerIntent{{ID: "local", Transport: "stdio", ExecutableRef: "server", Arguments: []MCPArgumentIntent{{Kind: "path", Ref: "settings"}}}}, executables, grants, nil)
			if err != nil || len(recipes) != 1 || len(recipes[0].Arguments) != 1 || recipes[0].Arguments[0].Value != settings.path {
				t.Fatalf("compile path-bound MCP recipe: %#v, %v", recipes, err)
			}
		})
	}
}

func TestMCPRecipeWorkspaceAliasIsRevalidated(t *testing.T) {
	root := t.TempDir()
	realOne := filepath.Join(root, "workspace-one")
	realTwo := filepath.Join(root, "workspace-two")
	alias := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	for _, directory := range []string{realOne, realTwo, filepath.Join(realOne, "bin"), filepath.Join(realTwo, "bin")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(realOne, "settings.json"), filepath.Join(realTwo, "settings.json")} {
		if err := os.WriteFile(path, []byte("selected"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(realOne, "bin", "server"), filepath.Join(realTwo, "bin", "server")} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(realOne, alias); err != nil {
		t.Fatal(err)
	}
	executables, err := ResolveExecutableGrants([]ExecutableGrantIntent{{ID: "server", ReferenceKind: ExecutableReferenceWorkspaceRelative, Path: "bin/server"}}, alias, sessions)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ResolveFilesystemGrants([]PathGrantIntent{{ID: "settings", Access: PathAccessReadOnly, Type: PathTypeFile, ReferenceKind: PathReferenceWorkspaceRelative, Path: "settings.json"}}, alias, sessions, WorkspaceAccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := CompileMCPRecipes([]MCPServerIntent{{ID: "local", Transport: "stdio", ExecutableRef: "server", Arguments: []MCPArgumentIntent{{Kind: "path", Ref: "settings"}}}}, executables, paths, nil)
	if err != nil || len(recipes) != 1 {
		t.Fatalf("compile alias-bound recipe: %#v, %v", recipes, err)
	}
	recipe := recipes[0]
	if !recipeWorkspaceIdentityMatches(recipe.WorkspacePath, recipe.WorkspaceCanonicalPath, recipe.WorkspaceIdentity, recipe.WorkspaceWitness) || !recipeWorkspaceIdentityMatches(recipe.Arguments[0].WorkspacePath, recipe.Arguments[0].WorkspaceCanonicalPath, recipe.Arguments[0].WorkspaceIdentity, recipe.Arguments[0].WorkspaceWitness) {
		t.Fatal("unchanged workspace alias was refused")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTwo, alias); err != nil {
		t.Fatal(err)
	}
	if recipeWorkspaceIdentityMatches(recipe.WorkspacePath, recipe.WorkspaceCanonicalPath, recipe.WorkspaceIdentity, recipe.WorkspaceWitness) || recipeWorkspaceIdentityMatches(recipe.Arguments[0].WorkspacePath, recipe.Arguments[0].WorkspaceCanonicalPath, recipe.Arguments[0].WorkspaceIdentity, recipe.Arguments[0].WorkspaceWitness) {
		t.Fatal("retargeted workspace alias was accepted")
	}
}

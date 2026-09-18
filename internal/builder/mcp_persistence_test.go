package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	skilltypes "github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestMCPBuilderPersistsEditDeleteAndRefusesDanglingCapabilities(t *testing.T) {
	ctx := context.Background()
	skills, _ := newBuilderFixture(t)
	workspace, e := commonprofile.NewWorkspaceBinding()
	if e != nil {
		t.Fatal(e)
	}
	paths, e := commonprofile.NewPathsBinding()
	if e != nil {
		t.Fatal(e)
	}
	executables, e := commonprofile.NewExecutablesBinding()
	if e != nil {
		t.Fatal(e)
	}
	environment, e := commonprofile.NewEnvironmentBinding()
	if e != nil {
		t.Fatal(e)
	}
	mcp, e := commonprofile.NewMCPBinding()
	if e != nil {
		t.Fatal(e)
	}
	registry, e := category.NewRegistry("devin", skills.Registration(), workspace.Registration(), paths.Registration(), executables.Registration(), environment.Registration(), mcp.Registration())
	if e != nil {
		t.Fatal(e)
	}
	// Resolve no host sources: this is the actual Builder/save/store transaction path.
	skillEditor, e := RegisterSkillsEditor(skills, func(context.Context) ([]skilltypes.SkillBundle, error) { return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	workspaceEditor, e := RegisterWorkspaceEditor(workspace)
	if e != nil {
		t.Fatal(e)
	}
	pathEditor, e := RegisterPathsEditor(paths)
	if e != nil {
		t.Fatal(e)
	}
	exeEditor, e := RegisterExecutablesEditor(executables)
	if e != nil {
		t.Fatal(e)
	}
	envEditor, e := RegisterEnvironmentEditor(environment)
	if e != nil {
		t.Fatal(e)
	}
	mcpRegistration, e := RegisterMCPEditor(mcp)
	if e != nil {
		t.Fatal(e)
	}
	editors, e := NewEditorRegistry(registry, skillEditor, workspaceEditor, pathEditor, exeEditor, envEditor, mcpRegistration)
	if e != nil {
		t.Fatal(e)
	}
	home := t.TempDir()
	store := profile.NewStore(home, registry)
	repo := profilerepo.New(home)
	document := []byte(`{"version":3,"name":"persisted","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"executables":{"version":1,"selection":{"entries":[{"id":"exe","reference":{"kind":"fixed-search-name","name":"true"}}]}},"paths":{"version":1,"selection":{"entries":[{"id":"input","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"input.txt"}}]}},"environment":{"version":1,"selection":{"entries":[{"id":"flag","destination":"MCP_FLAG","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_FLAG"},"classification":"non-secret","required":true},{"id":"token","destination":"MCP_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN"},"classification":"secret","required":true}]}},"mcp":{"version":1,"selection":{"servers":[{"id":"first","transport":"stdio","executableRef":"exe","arguments":[{"kind":"environment","ref":"flag"},{"kind":"path","ref":"input"}],"inputRefs":["input"],"environmentRefs":["flag","token"],"disabledTools":["blocked"]},{"id":"second","transport":"stdio","executableRef":"exe","arguments":[],"inputRefs":[],"environmentRefs":[],"disabledTools":["second_blocked"]}]}}},"overlays":{"devin":{"version":1}}}`)
	candidate, e := registry.Decode(document)
	if e != nil {
		t.Fatal(e)
	}
	draft, e := registry.DraftFromProfile(candidate)
	if e != nil {
		t.Fatal(e)
	}
	save := func(d category.Draft, wantSuccess bool) {
		t.Helper()
		base, err := repo.Read(ctx, "persisted")
		if err != nil {
			t.Fatal(err)
		}
		model, err := NewModel("persisted", d, editors)
		if err != nil {
			t.Fatal(err)
		}
		model = model.WithSaver(func(ctx context.Context, snapshot category.Draft) (string, error) {
			candidate, err := registry.NewProfile("persisted", snapshot)
			if err != nil {
				return "", err
			}
			if !base.Exists {
				return store.CreateContext(ctx, candidate)
			}
			_, data, err := profile.Canonicalize(registry, candidate)
			if err != nil {
				return "", err
			}
			_, err = repo.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.ReplaceRequest{Name: "persisted", Expected: base.Revision, Bytes: data}, Operation: "edit"})
			return filepath.Join(home, "profiles", "persisted.json"), err
		})
		started, command := model.startSave()
		if command == nil {
			t.Fatal("missing real save command")
		}
		finished, _ := started.(Model).Update(command())
		model = finished.(Model)
		after, err := repo.Read(ctx, "persisted")
		if err != nil {
			t.Fatal(err)
		}
		if wantSuccess {
			if !model.Outcome().Create || !after.Exists || after.Revision == base.Revision {
				t.Fatalf("save not committed: outcome=%+v error=%v", model.Outcome(), model.saveError)
			}
		} else {
			if model.screen != saveFailureScreen || model.saveError == nil || !strings.Contains(model.saveError.Error(), "mcp") {
				t.Fatalf("missing reference refusal: %v", model.saveError)
			}
			if after.Revision != base.Revision || !bytes.Equal(after.Bytes, base.Bytes) {
				t.Fatal("refused save changed persisted bytes/revision")
			}
		}
	}
	reopen := func() mcpEditor {
		t.Helper()
		loaded, err := store.Load("persisted")
		if err != nil {
			t.Fatal(err)
		}
		draft, err := registry.DraftFromProfile(loaded)
		if err != nil {
			t.Fatal(err)
		}
		return mcpRegistration.new(draft).(mcpEditor)
	}
	save(draft, true)
	editor := reopen()
	editor = mcpEditorPress(editor, "enter")
	edited := commonprofile.MCPServer{ID: "first", Transport: "stdio", ExecutableRef: "exe", Arguments: []commonprofile.MCPArgument{{Kind: "path", Ref: "input"}, {Kind: "environment", Ref: "flag"}}, InputRefs: []string{"input"}, EnvironmentRefs: []string{"flag", "token"}, DisabledTools: []string{"blocked", "write"}}
	data, e := json.Marshal(edited)
	if e != nil {
		t.Fatal(e)
	}
	editor.input = string(data)
	editor = mcpEditorPress(editor, "enter")
	save(editor.Draft(), true)
	editor = reopen()
	selected, e := category.Selection(editor.Draft(), mcp)
	if e != nil || len(selected.Servers) != 2 || !reflect.DeepEqual(selected.Servers[0], edited) {
		t.Fatalf("persisted edit lost ordered refs/filter: %+v %v", selected, e)
	}
	for _, kind := range []string{"executable removal", "executable rename", "input removal", "environment removal"} {
		t.Run(kind, func(t *testing.T) {
			d, err := editor.Draft().Clone()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "executable removal":
				err = category.SetSelection(&d, executables, commonprofile.ExecutableSelection{Entries: []commonprofile.ExecutableEntry{}})
			case "executable rename":
				v, _ := category.Selection(d, executables)
				v.Entries[0].ID = "renamed"
				err = category.SetSelection(&d, executables, v)
			case "input removal":
				err = category.SetSelection(&d, paths, commonprofile.PathSelection{Entries: []commonprofile.PathEntry{}})
			case "environment removal":
				v, _ := category.Selection(d, environment)
				v.Entries = v.Entries[:1]
				err = category.SetSelection(&d, environment, v)
			}
			if err != nil {
				t.Fatal(err)
			}
			save(d, false)
		})
	}
	// Reopen from disk after every refusal; delete only the second descriptor.
	editor = reopen()
	editor.cursor = 1
	editor = mcpEditorPress(editor, "d")
	save(editor.Draft(), true)
	editor = reopen()
	selected, e = category.Selection(editor.Draft(), mcp)
	if e != nil || len(selected.Servers) != 1 || !reflect.DeepEqual(selected.Servers[0], edited) {
		t.Fatalf("persisted deletion changed survivor: %+v %v", selected, e)
	}
	history, e := repo.History(ctx, profilerepo.HistorySelector{Name: "persisted"}, 100)
	if e != nil || len(history.Events) != 3 {
		t.Fatalf("expected create/edit/delete only: %+v %v", history, e)
	}
}

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestProfileInspectionHelpGrammar(t *testing.T) {
	for _, args := range []string{"help profile", "profile --help", "help profile list", "profile list --help", "help profile show", "profile show --help", "profile show --json example --help", "profile show example --help --json"} {
		var out, errOut bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), strings.Fields(args))
		if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "Usage: acs profile") {
			t.Errorf("%s: code %d, %s", args, code, &errOut)
		}
	}
}

func TestInspectionRejectsSyntaxWithoutRuntime(t *testing.T) {
	for _, args := range []string{"profile", "profile list example", "profile list --json --json", "profile list --json=yes", "profile show", "profile show --json", "profile show example extra", "profile show --json example extra", "profile show example --json --json", "profile show example -- --anything", "profile show --name example", "profile show example --dry-run", "profile show example --backend none", "profile show example --no-sandbox", "profile show example --help --unknown", "help profile show example", "devin example", "sandbox example", "codex auth list example", "devin create-profile example"} {
		var out, errOut bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), strings.Fields(args))
		if code != 1 || out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("syntax %q: code %d stdout %q stderr %q", args, code, &out, &errOut)
		}
	}
}

type forbiddenInspectionRuntime struct{ t *testing.T }

func (f forbiddenInspectionRuntime) Create(profile.Profile) (string, error) {
	f.t.Fatal("inspection wrote launch store")
	return "", nil
}
func (f forbiddenInspectionRuntime) CreateContext(context.Context, profile.Profile) (string, error) {
	f.t.Fatal("inspection wrote launch store")
	return "", nil
}
func (f forbiddenInspectionRuntime) Load(string) (profile.Profile, error) {
	f.t.Fatal("inspection called launch codec/store")
	return profile.Profile{}, nil
}
func (f forbiddenInspectionRuntime) PlanLaunch(context.Context, string, string, category.ResolvedProfile) (launch.Plan, error) {
	f.t.Fatal("inspection called planner")
	return launch.Plan{}, nil
}
func (f forbiddenInspectionRuntime) Launch(context.Context, string, string, category.ResolvedProfile, launch.Terminal) (int, error) {
	f.t.Fatal("inspection called process/Session launcher")
	return 1, nil
}
func TestInspectionNeverUsesLaunchOrAuthenticationBoundaries(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(`{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"removed"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{"profile list", "profile list --json", "profile show example", "profile show --json example", "profile show absent --json", "profile show ../private --json", "profile show example --help"} {
		var out, errOut bytes.Buffer
		forbidden := forbiddenInspectionRuntime{t}
		auth := &recordingCodexAuthRegistry{}
		// Categories deliberately absent: resolution cannot succeed. Every launch
		// collaborator fails the test if called; auth counters also catch recovery.
		app := cli.App{Inspector: profileinspect.Store{Home: home}, Profiles: forbidden, Planner: forbidden, SandboxPlanner: forbidden, Launcher: forbidden, SandboxLauncher: forbidden, CodexAuth: auth, Output: &out, ErrorOutput: &errOut, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("inspection checked terminal"); return false }}
		code := app.Run(context.Background(), strings.Fields(args))
		want := 0
		if strings.Contains(args, "absent") || strings.Contains(args, "../") {
			want = 1
		}
		if code != want {
			t.Fatalf("%s: code %d %s", args, code, &errOut)
		}
		if auth.loginCalls+auth.listCalls+auth.logoutCalls+auth.statusCalls+auth.recoverCalls != 0 {
			t.Fatal("inspection accessed authentication provider")
		}
		if strings.ContainsRune(out.String(), '\x1b') {
			t.Fatal("raw control in human output")
		}
	}
}
func TestInspectionEarlyDispatchHomeFailureIsStructured(t *testing.T) {
	for _, args := range []string{"profile list --json", "profile show example --json"} {
		var out, errOut bytes.Buffer
		app := cli.App{Output: &out, ErrorOutput: &errOut}
		handled, code := app.RunProfileInspection(strings.Fields(args), func() (string, error) { return "", errors.New("private home error") })
		if !handled || code != 1 || errOut.Len() != 0 || !strings.Contains(out.String(), `"code":"storage_unavailable"`) || strings.Contains(out.String(), "private") {
			t.Fatalf("%s: %d %s %s", args, code, &out, &errOut)
		}
	}
	for _, args := range []string{"profile list --help", "profile show example --help", "profile show", "profile list --unknown", "devin --profile example"} {
		handled, _ := (cli.App{}).RunProfileInspection(strings.Fields(args), func() (string, error) { t.Fatal("unexpected home access"); return "", nil })
		if handled {
			t.Fatal("accepted non-inspection command")
		}
	}
}

func TestInspectionHumanGuidanceAndControlEscaping(t *testing.T) {
	home := t.TempDir()
	var out, errOut bytes.Buffer
	app := cli.App{Inspector: profileinspect.Store{Home: home}, Output: &out, ErrorOutput: &errOut}
	if code := app.Run(context.Background(), []string{"profile", "list"}); code != 0 || !strings.Contains(out.String(), "acs devin create-profile --name NAME") {
		t.Fatalf("missing guidance: %s", &out)
	}
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(`{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"skill\u001b[31m\n"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "example"}); code != 0 {
		t.Fatal("show failed")
	}
	if strings.ContainsRune(out.String(), '\x1b') || !strings.Contains(out.String(), `skill\x1b[31m\n`) || !strings.Contains(out.String(), "unchecked") {
		t.Fatalf("unsafe human output: %q", &out)
	}
}

func TestInspectionInvalidNamePrecedesHomeDiscovery(t *testing.T) {
	for _, args := range [][]string{{"profile", "show", "../private", "--json"}, {"profile", "show", "--json", "bad\x1bname"}, {"profile", "show", "../private"}} {
		var out, errOut bytes.Buffer
		handled, code := (cli.App{Output: &out, ErrorOutput: &errOut}).RunProfileInspection(args, func() (string, error) { t.Fatal("invalid name called home resolver"); return "", nil })
		if !handled || code != 1 || errOut.Len() != 0 || !strings.Contains(out.String(), "invalid_name") || strings.Contains(out.String(), "private") || strings.ContainsRune(out.String(), '\x1b') {
			t.Fatalf("invalid-name result: %d %q %q", code, &out, &errOut)
		}
	}
}

func (f forbiddenInspectionRuntime) RecoverContext(context.Context) error {
	panic("passive inspection invoked Profile recovery")
}

func TestInspectionCountsEachCapabilityWithoutDisclosingPrivateSelections(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"version":3,"name":"example","common":{
		"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"},{"source":"devin-config","relativePath":"build"}]},
		"workspace":{"version":1,"selection":{"access":"read-write"}},
		"instructions":{"version":1,"selection":[{"source":"acs-instructions","relativePath":"guide.md"}]},
		"paths":{"version":1,"selection":{"entries":[{"id":"input","access":"read-only","type":"file","reference":{"kind":"local-absolute","path":"/private/inspection-sentinel"}}]}},
		"exclusions":{"version":1,"selection":{"entries":[{"id":"hidden","type":"directory","reference":{"kind":"local-absolute","path":"/private/exclusion-sentinel"}}]}},
		"executables":{"version":1,"selection":{"entries":[{"id":"server-bin","reference":{"kind":"fixed-search-name","name":"private-executable-sentinel"}}]}},
		"environment":{"version":1,"selection":{"entries":[{"id":"token","destination":"API_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"PRIVATE_ENV_SENTINEL"},"required":true,"classification":"secret"},{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"PRIVATE_MODE_SENTINEL"},"required":false,"classification":"non-secret"}]}},
		"mcp":{"version":1,"selection":{"servers":[{"id":"private-server-sentinel","transport":"stdio","executableRef":"server-bin","arguments":[],"inputRefs":["input"],"environmentRefs":["token"]}]}}
	},"overlays":{"codex":{"version":1,"authRef":"private-auth-sentinel"}}}`
	if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"profile", "list"}, {"profile", "show", "example"}, {"profile", "list", "--json"}, {"profile", "show", "example", "--json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			forbidden := forbiddenInspectionRuntime{t}
			auth := &recordingCodexAuthRegistry{}
			app := cli.App{Inspector: profileinspect.Store{Home: home}, Profiles: forbidden, Planner: forbidden, Launcher: forbidden, CodexAuth: auth, Output: &out, ErrorOutput: &errOut}
			if code := app.Run(context.Background(), args); code != 0 || errOut.Len() != 0 {
				t.Fatalf("code %d: %s %s", code, &out, &errOut)
			}
			for _, secret := range []string{"inspection-sentinel", "exclusion-sentinel", "private-executable-sentinel", "PRIVATE_ENV_SENTINEL", "PRIVATE_MODE_SENTINEL", "private-server-sentinel", "private-auth-sentinel"} {
				if strings.Contains(out.String(), secret) {
					t.Fatalf("private selection leaked: %s", secret)
				}
			}
			if auth.loginCalls+auth.listCalls+auth.logoutCalls+auth.statusCalls+auth.recoverCalls != 0 {
				t.Fatal("inspection accessed authentication provider")
			}
			if args[len(args)-1] == "--json" {
				var result struct {
					Entries []struct{ Categories []map[string]json.RawMessage }
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Entries) != 1 || len(result.Entries[0].Categories) != 8 {
					t.Fatalf("categories: %s", &out)
				}
				seen := map[string]bool{}
				for _, item := range result.Entries[0].Categories {
					var id string
					if err := json.Unmarshal(item["id"], &id); err != nil || seen[id] || string(item["schemaVersion"]) != "1" {
						t.Fatalf("invalid category metadata: %v", item)
					}
					seen[id] = true
					wantFields := 2
					switch id {
					case "skills":
						wantFields = 3
						if string(item["selection"]) != `[{"source":"devin-config","relativePath":"build"},{"source":"shared-agents","relativePath":"review"}]` {
							t.Fatalf("changed Skill references: %s", item["selection"])
						}
					case "instructions":
						wantFields = 3
						if string(item["instructions"]) != `[{"source":"acs-instructions","relativePath":"guide.md"}]` {
							t.Fatalf("changed instruction references: %s", item["instructions"])
						}
					case "workspace", "paths", "exclusions", "executables", "environment", "mcp":
					default:
						t.Fatalf("unexpected category: %q", id)
					}
					if len(item) != wantFields {
						t.Fatalf("changed category fields: %v", item)
					}
					for key := range item {
						if key != "id" && key != "schemaVersion" && key != "selection" && key != "instructions" {
							t.Fatalf("changed JSON contract: %s", key)
						}
					}
				}
				return
			}
			for id, count := range map[string]int{"skills": 2, "instructions": 1, "paths": 1, "exclusions": 1, "executables": 1, "environment": 2, "mcp": 1} {
				want := fmt.Sprintf("%s: %d selected; stored category version: 1", id, count)
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in %s", want, &out)
				}
			}
			if !strings.Contains(out.String(), "workspace: configured; stored category version: 1") || !strings.Contains(out.String(), "common workspace access: read-write") {
				t.Errorf("misleading workspace summary: %s", &out)
			}
		})
	}
}

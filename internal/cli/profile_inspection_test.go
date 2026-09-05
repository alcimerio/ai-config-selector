package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
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
func (f forbiddenInspectionRuntime) PlanLaunch(context.Context, string, category.ResolvedProfile) (launch.Plan, error) {
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

//go:build darwin

package codexauthresource_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
)

// A fixed test-only trampoline adds app-server stdio to the reviewed runtime.
// The installed candidate still owns Profile resolution, authentication,
// preflight, native policy, Session projection and descendant cleanup. The
// synthetic identity sends no account credential or model request.
func TestNativeInstalledACSFilesystemExclusionCatalog(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("explicit isolated native authentication fixture required")
	}
	candidate, target, archive := os.Getenv("ACS_PROMOTED_BINARY"), os.Getenv("ACS_TEST_CODEX_BINARY"), os.Getenv("ACS_TEST_CODEX_ARCHIVE")
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(target) || !filepath.IsAbs(archive) {
		t.Fatal("installed candidate and locked runtime paths are required")
	}
	assertLockedCodexIdentity(t, archive, target)
	hostTarget := filepath.Join(filepath.Dir(target), "codex-code-mode-host")
	hostArchive := filepath.Join(filepath.Dir(archive), strings.Replace(filepath.Base(archive), "codex_", "codex_code_mode_host_", 1))
	assertLockedCodexHostIdentity(t, hostArchive, hostTarget)
	codexauthresource.UseIsolatedTestKeychainForComposition(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, workspace, tools := filepath.Join(root, "home"), filepath.Join(root, "workspace"), filepath.Join(root, "tools")
	for _, path := range []string{home, workspace, tools} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configureInstalledCandidateKeychainContext(t, home, tools)
	buildSyntheticLoginTarget(t, filepath.Join(tools, "codex"))
	prepareInstalledSyntheticIdentity(t, candidate, home, tools, workspace, "exclusion-fixture")
	runtimeRoot := filepath.Join(home, "targets")
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{target, hostTarget} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runtimeRoot, filepath.Base(source)), data, 0500); err != nil {
			t.Fatal(err)
		}
	}
	hostBytes, err := os.ReadFile(hostTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "codex-code-mode-host"), hostBytes, 0500); err != nil {
		t.Fatal(err)
	}
	installedTarget := filepath.Join(runtimeRoot, "codex")
	// Compile the trampoline rather than use a script interpreter with incidental
	// grants. All paths below are disposable synthetic fixture paths.
	source := filepath.Join(root, "catalog-trampoline.c")
	program := `#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){char **out=calloc((size_t)argc+4,sizeof(char*)); if(!out)return 90;
 out[0]=` + strconv.Quote(installedTarget) + `;int version=0;for(int i=1;i<argc;i++){out[i]=argv[i];if(strcmp(argv[i],"--version")==0)version=1;}
 if(!version){out[argc]="app-server";out[argc+1]="--stdio";}
 execv(out[0],out);return 91;}`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := nativeCommand(t, "/usr/bin/clang", "-Os", source, "-o", filepath.Join(tools, "codex")).CombinedOutput(); err != nil {
		t.Fatalf("compile trampoline: %v %s", err, output)
	}
	if err := os.Mkdir(filepath.Join(workspace, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"excluded_fixture", "permitted_fixture"} {
		writeNativeSkill(t, filepath.Join(workspace, ".agents", "skills", name), name, "fixture-only")
	}
	for _, scenario := range []string{"baseline", "bundle", "root"} {
		t.Run(scenario, func(t *testing.T) {
			entries := []any{}
			if scenario != "baseline" {
				path := ".agents/skills"
				if scenario == "bundle" {
					path += "/excluded_fixture"
				}
				entries = append(entries, map[string]any{"id": "hidden", "type": "directory", "reference": map[string]string{"kind": "workspace-relative", "path": path}})
			}
			executables := []any{}
			for _, name := range []string{"codex", "codex-code-mode-host"} {
				id := name
				if name == "codex" {
					id = "runtime"
				}
				executables = append(executables, map[string]any{"id": id, "reference": map[string]string{"kind": "local-absolute", "path": filepath.Join(runtimeRoot, name)}})
			}
			document, _ := json.Marshal(map[string]any{"version": 1, "name": "catalog-" + scenario, "common": map[string]any{
				"skills": map[string]any{"version": 1, "selection": []any{}}, "workspace": map[string]any{"version": 1, "selection": map[string]string{"access": "read-only"}},
				"exclusions": map[string]any{"version": 1, "selection": map[string]any{"entries": entries}}, "executables": map[string]any{"version": 1, "selection": map[string]any{"entries": executables}},
			}, "overlays": map[string]any{"codex": map[string]any{"version": 1, "authRef": "exclusion-fixture"}}})
			file := filepath.Join(home, "catalog-"+scenario+".json")
			if err := os.WriteFile(file, document, 0600); err != nil {
				t.Fatal(err)
			}
			create := nativeCommand(t, candidate, "profile", "create", "--file", file)
			create.Dir = workspace
			create.Env = nativeCandidateEnvironment(home, tools)
			if output, err := create.CombinedOutput(); err != nil {
				t.Fatalf("create: %v %s", err, output)
			}
			got := installedExclusionCatalog(t, candidate, home, tools, workspace, "catalog-"+scenario)
			want := []string{"excluded_fixture", "permitted_fixture"}
			if scenario == "bundle" {
				want = []string{"permitted_fixture"}
			}
			if scenario == "root" {
				want = []string{}
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("catalog=%v want=%v", got, want)
			}
			assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
		})
	}
}

func installedExclusionCatalog(t *testing.T, candidate, home, tools, workspace, profile string) []string {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	state, err := term.MakeRaw(terminal.Fd())
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(terminal.Fd(), state)
	command := nativeCommandWithTimeout(t, 3*time.Minute, candidate, "codex", "--profile", profile)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	terminal.Close()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			command.Process.Signal(syscall.SIGTERM)
			select {
			case <-wait:
			case <-time.After(10 * time.Second):
				command.Process.Kill()
				<-wait
			}
		}
	}()
	capture := &nativeSafeCapture{}
	lines := make(chan []byte, 32)
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		scanner := bufio.NewScanner(master)
		scanner.Buffer(make([]byte, 4096), 2<<20)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			capture.Write(append(line, '\n'))
			if json.Valid(line) {
				select {
				case lines <- line:
				case <-readDone:
					return
				}
			}
		}
		close(lines)
	}()
	request := func(id int, method string, params any) json.RawMessage {
		encoded, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
		if _, err := master.Write(append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("catalog protocol ended: %s", capture.BoundedString(1200))
				}
				var response struct {
					ID     *int            `json:"id"`
					Result json.RawMessage `json:"result"`
					Error  json.RawMessage `json:"error"`
				}
				if json.Unmarshal(line, &response) == nil && response.ID != nil && *response.ID == id {
					if len(response.Error) != 0 {
						t.Fatalf("catalog protocol error: %s", response.Error)
					}
					return response.Result
				}
			case <-timer.C:
				t.Fatalf("catalog protocol timeout for %s: %s", method, capture.BoundedString(1200))
			}
		}
	}
	request(1, "initialize", map[string]any{"clientInfo": map[string]string{"name": "exclusion-fixture", "version": "1"}, "capabilities": map[string]bool{"experimentalApi": true}})
	raw := request(2, "skills/list", map[string]any{"cwds": []string{workspace}, "forceReload": true})
	var result struct {
		Data []struct {
			Errors []json.RawMessage `json:"errors"`
			Skills []struct {
				Name string `json:"name"`
			} `json:"skills"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Data) != 1 || len(result.Data[0].Errors) != 0 {
		t.Fatalf("catalog result: %v %s", err, raw)
	}
	names := []string{}
	for _, skill := range result.Data[0].Skills {
		if strings.HasSuffix(skill.Name, "_fixture") {
			names = append(names, skill.Name)
		}
	}
	sort.Strings(names)
	command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-wait:
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || (exit.ExitCode() != 143 && exit.ExitCode() != 130) {
				t.Fatalf("catalog cleanup: %v", err)
			}
		}
		finished = true
	case <-time.After(10 * time.Second):
		t.Fatal("catalog cleanup timeout")
	}
	return names
}

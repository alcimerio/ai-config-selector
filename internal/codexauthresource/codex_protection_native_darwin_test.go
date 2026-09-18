//go:build darwin

package codexauthresource_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "codex" {
		runCodexProtectionWitness(os.Args[1:])
		return
	}
	if filepath.Base(os.Args[0]) == "codex-code-mode-host" {
		receipt := os.Getenv("ACS_CODEX_COMPANION_RECEIPT")
		if receipt == "" {
			os.Exit(77)
		}
		executable, err := os.Executable()
		if err != nil {
			os.Exit(78)
		}
		if err := os.WriteFile(receipt+".pending", []byte("codex-code-mode-host\n"+executable+"\n"), 0o600); err != nil || os.Rename(receipt+".pending", receipt) != nil {
			os.Exit(79)
		}
		return
	}
	os.Exit(m.Run())
}

func runCodexProtectionWitness(args []string) {
	valid, version := classifyCodexWitnessArgs(args)
	if !valid {
		os.Exit(76)
	}
	if version {
		fmt.Println("codex-cli 0.149.1")
		return
	}
	home := os.Getenv("HOME")
	workspace, _ := os.Getwd()
	ready, start, done, release := filepath.Join(workspace, ".codex-protection-ready"), filepath.Join(workspace, ".codex-protection-start"), filepath.Join(workspace, ".codex-protection-done"), filepath.Join(workspace, ".codex-protection-release")
	if os.WriteFile(ready+".pending", []byte(home+"\n"), 0o600) != nil || os.Rename(ready+".pending", ready) != nil || !waitCodexProtectionFile(start) {
		os.Exit(74)
	}
	companion := filepath.Join(filepath.Dir(mustCodexExecutable()), "codex-code-mode-host")
	if _, err := os.Stat(companion); err != nil {
		os.Exit(80)
	}
	command := exec.Command(companion)
	command.Env = append(os.Environ(), "ACS_CODEX_COMPANION_RECEIPT="+filepath.Join(workspace, ".codex-companion-receipt"))
	if err := command.Run(); err != nil {
		os.Exit(81)
	}
	results := map[string]string{}
	for _, path := range []string{filepath.Join(home, ".acs", "mcp", "recipes.json"), filepath.Join(home, ".codex", "config.toml")} {
		codexProtectionAttempts(path, home, workspace, results)
	}
	ordinary := filepath.Join(home, "ordinary-codex-marker")
	if os.WriteFile(ordinary, []byte("ordinary-codex\n"), 0o600) == nil {
		results["ordinary-home"] = "ok"
	} else {
		results["ordinary-home"] = "failed"
	}
	if os.WriteFile(filepath.Join(home, ".codex", "ordinary-codex-sibling"), []byte("ordinary-codex-sibling\n"), 0o600) == nil {
		results["ordinary-codex-sibling"] = "ok"
	} else {
		results["ordinary-codex-sibling"] = "failed"
	}
	data, _ := json.Marshal(results)
	if os.WriteFile(done+".pending", data, 0o600) != nil || os.Rename(done+".pending", done) != nil || !waitCodexProtectionFile(release) {
		os.Exit(75)
	}
}

func classifyCodexWitnessArgs(args []string) (bool, bool) {
	for index := 0; index < len(args); {
		if args[index] != "-c" || index+1 >= len(args) || !strings.Contains(args[index+1], "=") {
			version := index+1 == len(args) && args[index] == "--version"
			return version, version
		}
		index += 2
	}
	return true, false
}

func mustCodexExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func waitCodexProtectionFile(path string) bool {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func codexProtectionError(err error) string {
	if err == nil {
		return "unexpected-success"
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return "denied"
	}
	return "operation-error"
}

func codexProtectionAttempts(path, home, workspace string, results map[string]string) {
	if _, err := os.ReadFile(path); err != nil {
		results[filepath.Base(path)+"-setup"] = codexProtectionError(err)
		return
	}
	attempt := func(name string, f func() error) bool {
		err := f()
		results[name] = codexProtectionError(err)
		return err == nil
	}
	if attempt(filepath.Base(path)+"-overwrite", func() error { return os.WriteFile(path, []byte("overwrite\n"), 0o600) }) {
		return
	}
	if attempt(filepath.Base(path)+"-truncate", func() error { return os.Truncate(path, 0) }) {
		return
	}
	if attempt(filepath.Base(path)+"-unlink", func() error { return os.Remove(path) }) {
		return
	}
	replacement := filepath.Join(workspace, filepath.Base(path)+".replacement")
	if os.WriteFile(replacement, []byte("replacement\n"), 0o600) != nil {
		results[filepath.Base(path)+"-replacement-setup"] = "operation-error"
		return
	}
	if attempt(filepath.Base(path)+"-rename", func() error { return os.Rename(replacement, path) }) {
		return
	}
	stop := filepath.Dir(home)
	for ancestor := filepath.Dir(path); ancestor == stop || ancestor == home || strings.HasPrefix(ancestor, home+string(os.PathSeparator)); ancestor = filepath.Dir(ancestor) {
		renamed := filepath.Join(workspace, filepath.Base(ancestor)+".renamed")
		if attempt(filepath.Base(path)+"-ancestor-"+filepath.Base(ancestor), func() error { return os.Rename(ancestor, renamed) }) {
			return
		}
		_ = os.Remove(renamed)
	}
}

func TestCodexPublicProductionMCPProtection(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 for native Codex protection")
	}
	candidate := os.Getenv("ACS_PROMOTED_BINARY")
	if candidate == "" {
		t.Fatal("ACS_PROMOTED_BINARY is required")
	}
	codexauthresource.UseIsolatedTestKeychainForComposition(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, workspace, tools := filepath.Join(root, "home"), filepath.Join(root, "workspace"), filepath.Join(root, "tools")
	for _, dir := range []string{home, workspace, tools} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configureInstalledCandidateKeychainContext(t, home, tools)
	buildSyntheticLoginTarget(t, filepath.Join(tools, "codex"))
	runInstalledSyntheticLogin(t, candidate, home, tools, workspace, "interactive-coding")
	assertInstalledIdentityStatus(t, candidate, home, tools, workspace, "interactive-coding")
	os.Remove(filepath.Join(tools, "codex"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := copyCodexCompanion(executable, filepath.Join(tools, "codex")); err != nil {
		t.Fatal(err)
	}
	if err := copyCodexCompanion(executable, filepath.Join(tools, "codex-code-mode-host")); err != nil {
		t.Fatal(err)
	}
	writeNativeMCPServer(t, filepath.Join(workspace, "native-mcp-server.sh"))
	writeCodexProtectionProfile(t, home, "codex-protection")
	before := installedSessionSnapshot(t, candidate, home, tools, workspace)
	command := exec.Command(candidate, "codex", "--profile", "codex-protection")
	command.Dir = workspace
	command.Env = append(nativeCandidateEnvironment(home, tools), "ACS_NATIVE_MCP_ARGUMENT=argument")
	output := &nativeDiagnosticSink{}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	result := startNativeCodexProtectionCommand(command)
	defer settleNativeCodexProtectionCommand(command, result)
	sessionHome := waitCodexProtectionReady(t, filepath.Join(workspace, ".codex-protection-ready"), result, output)
	if !strings.HasPrefix(sessionHome, filepath.Join(home, ".acs", "sessions")+string(os.PathSeparator)) {
		t.Fatalf("invalid Session HOME %q", sessionHome)
	}
	protected := []string{filepath.Join(sessionHome, ".acs", "mcp", "recipes.json"), filepath.Join(sessionHome, ".codex", "config.toml")}
	type snapshot struct {
		data     []byte
		info     os.FileInfo
		dev, ino uint64
	}
	snapshots := map[string]snapshot{}
	for _, path := range protected {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Fatalf("generated Codex artifact %s: %v", path, err)
		}
		if filepath.Base(path) == "recipes.json" {
			var recipes []launch.MCPRecipe
			if json.Unmarshal(data, &recipes) != nil || len(recipes) != 1 || recipes[0].ID != "fixture" || recipes[0].ExecutableLogicalPath != filepath.Join(workspace, "native-mcp-server.sh") || len(recipes[0].Disabled) != 1 || recipes[0].Disabled[0] != "blocked" || len(recipes[0].Arguments) != 0 || len(recipes[0].EnvNames) != 0 {
				t.Fatalf("recipe projection is not the exact selected fixture")
			}
		}
		if filepath.Base(path) == "config.toml" {
			candidateCommand, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				t.Fatal(err)
			}
			expected := "[mcp_servers.\"fixture\"]\ncommand = " + strconv.Quote(candidateCommand) + "\nargs = [\"--acs-mcp-launch\", " + strconv.Quote(sessionHome) + ", \"fixture\"]\nenv_vars = []\ndisabled_tools = [\"blocked\"]\n\n"
			if bytes.Count(data, []byte("[mcp_servers.")) != 1 {
				t.Fatalf("Codex config has unexpected MCP section count")
			}
			start := bytes.Index(data, []byte("[mcp_servers."))
			if start < 0 {
				t.Fatalf("Codex config lacks bounded MCP section")
			}
			features := bytes.Index(data[start:], []byte("[features]"))
			if features < 0 {
				t.Fatalf("Codex config lacks bounded features section")
			}
			if string(data[start:start+features]) != expected {
				t.Fatalf("Codex config projection is not the selected fixture")
			}
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		dev, ino := nativeCodexFileIdentity(t, path)
		snapshots[path] = snapshot{data: data, info: info, dev: dev, ino: ino}
	}
	directories := map[string]snapshot{}
	for _, path := range protected {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			dev, ino := nativeCodexFileIdentity(t, dir)
			directories[dir] = snapshot{info: info, dev: dev, ino: ino}
			if dir == filepath.Dir(sessionHome) {
				break
			}
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex-protection-start"), []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	done := waitCodexProtectionFileContents(t, filepath.Join(workspace, ".codex-protection-done"))
	var receipts map[string]string
	if json.Unmarshal(done, &receipts) != nil {
		t.Fatal("invalid Codex protection receipts")
	}
	receiptPath := filepath.Join(workspace, ".codex-companion-receipt")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("missing companion receipt: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	privateRoot := filepath.Join(home, ".acs", "sessions.executables") + string(os.PathSeparator)
	if len(lines) != 2 || lines[0] != "codex-code-mode-host" || !strings.HasPrefix(lines[1], privateRoot) || filepath.Base(lines[1]) != "codex-code-mode-host" {
		t.Fatalf("invalid private companion receipt %q", string(data))
	}
	if strings.HasPrefix(lines[1], filepath.Join(tools, "codex-code-mode-host")) {
		t.Fatalf("companion receipt used source sibling: %q", string(data))
	}
	expected := map[string]bool{"ordinary-home": true, "ordinary-codex-sibling": true}
	for _, path := range protected {
		for _, op := range []string{"overwrite", "truncate", "unlink", "rename"} {
			expected[filepath.Base(path)+"-"+op] = true
		}
		for dir := filepath.Dir(path); dir == filepath.Dir(sessionHome) || dir == sessionHome || strings.HasPrefix(dir, sessionHome+string(os.PathSeparator)); dir = filepath.Dir(dir) {
			expected[filepath.Base(path)+"-ancestor-"+filepath.Base(dir)] = true
		}
	}
	if len(receipts) != len(expected) {
		t.Fatalf("Codex protection receipt keys=%v want=%v", receipts, expected)
	}
	for key := range expected {
		if receipts[key] != "ok" && receipts[key] != "denied" {
			t.Fatalf("missing/invalid Codex receipt %s=%q", key, receipts[key])
		}
		if key != "ordinary-home" && key != "ordinary-codex-sibling" && receipts[key] != "denied" {
			t.Fatalf("Codex protection receipt %s=%q", key, receipts[key])
		}
	}
	if receipts["ordinary-home"] != "ok" {
		t.Fatal("ordinary Codex HOME write failed")
	}
	if receipts["ordinary-codex-sibling"] != "ok" {
		t.Fatal("ordinary Codex sibling write failed")
	}
	if data, err := os.ReadFile(filepath.Join(sessionHome, "ordinary-codex-marker")); err != nil || string(data) != "ordinary-codex\n" {
		t.Fatalf("ordinary Codex marker=(%q,%v)", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(sessionHome, ".codex", "ordinary-codex-sibling")); err != nil || string(data) != "ordinary-codex-sibling\n" {
		t.Fatalf("ordinary Codex sibling=(%q,%v)", data, err)
	}
	for path, data := range snapshots {
		current, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		dev, ino := nativeCodexFileIdentity(t, path)
		before := data
		if err != nil || statErr != nil || !bytes.Equal(current, before.data) || info.Mode() != before.info.Mode() || dev != before.dev || ino != before.ino {
			t.Fatalf("Codex protected artifact changed: %s", path)
		}
	}
	for path, before := range directories {
		info, err := os.Stat(path)
		dev, ino := nativeCodexFileIdentity(t, path)
		if err != nil || info.Mode() != before.info.Mode() || dev != before.dev || ino != before.ino {
			t.Fatalf("Codex protected directory changed: %s", path)
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex-protection-release"), []byte("release\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitNativeCodexProtectionCommand(result, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
	assertNewRemovedInstalledSessions(t, candidate, home, tools, workspace, before, "codex")
}

func writeCodexProtectionProfile(t *testing.T, home, name string) {
	t.Helper()
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	document := `{"version":3,"name":"` + name + `","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-write"}},"executables":{"version":1,"selection":{"entries":[{"id":"mcp-server","reference":{"kind":"workspace-relative","path":"native-mcp-server.sh"}}]}},"mcp":{"version":1,"selection":{"servers":[{"id":"fixture","transport":"stdio","executableRef":"mcp-server","arguments":[],"inputRefs":[],"environmentRefs":[],"disabledTools":["blocked"]}]}}},"overlays":{"codex":{"version":1,"authRef":"interactive-coding"}}}`
	if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
}

func copyCodexCompanion(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination, data, info.Mode().Perm()|0o111); err != nil {
		return err
	}
	return os.Chmod(destination, 0o700)
}

type nativeCodexProtectionResult struct {
	done chan struct{}
	err  error
}

func startNativeCodexProtectionCommand(command *exec.Cmd) *nativeCodexProtectionResult {
	r := &nativeCodexProtectionResult{done: make(chan struct{})}
	go func() { r.err = command.Wait(); close(r.done) }()
	return r
}
func waitNativeCodexProtectionCommand(r *nativeCodexProtectionResult, d time.Duration) error {
	select {
	case <-r.done:
		return r.err
	case <-time.After(d):
		return fmt.Errorf("Codex protection witness did not settle")
	}
}

func settleNativeCodexProtectionCommand(command *exec.Cmd, result *nativeCodexProtectionResult) {
	if waitNativeCodexProtectionCommand(result, 2*time.Second) == nil {
		return
	}
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	_ = waitNativeCodexProtectionCommand(result, 2*time.Second)
}
func waitCodexProtectionFileContents(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
	return nil
}

func waitCodexProtectionReady(t *testing.T, path string, result *nativeCodexProtectionResult, output *nativeDiagnosticSink) string {
	t.Helper()
	ready, category := waitCodexProtectionReadyState(path, result, 30*time.Second)
	if category != "" {
		outputState := "no-output"
		if output.Present() {
			outputState = "output-present"
		}
		t.Fatalf("Codex protection readiness %s (%s)", category, outputState)
	}
	return ready
}

func waitCodexProtectionReadyState(path string, result *nativeCodexProtectionResult, limit time.Duration) (string, string) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
				return strings.TrimSpace(string(data)), ""
			}
		case <-result.done:
			return "", nativeProtectionExitCategory(result)
		case <-deadline.C:
			return "", "timeout"
		}
	}
}

type nativeDiagnosticSink struct {
	mutex   sync.Mutex
	present bool
}

func (sink *nativeDiagnosticSink) Write(p []byte) (int, error) {
	sink.mutex.Lock()
	sink.present = sink.present || len(p) != 0
	sink.mutex.Unlock()
	return len(p), nil
}

func (sink *nativeDiagnosticSink) Present() bool {
	sink.mutex.Lock()
	present := sink.present
	sink.mutex.Unlock()
	return present
}

func nativeProtectionExitCategory(result *nativeCodexProtectionResult) string {
	if result.err == nil {
		return "early-exit-success"
	}
	if exit, ok := result.err.(*exec.ExitError); ok && exit.ProcessState != nil {
		if status, statusOK := exit.ProcessState.Sys().(syscall.WaitStatus); statusOK && status.Signaled() {
			return "early-exit-signal"
		}
	}
	return "early-exit"
}

func TestCodexWitnessArgumentClassifier(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		valid, version bool
	}{
		{"production version", []string{"-c", "a=b", "-c", "c=d", "--version"}, true, true},
		{"interactive", []string{"-c", "a=b", "-c", "c=d"}, true, false},
		{"malformed", []string{"-c", "missing"}, false, false},
		{"nonterminal version", []string{"--version", "extra"}, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid, version := classifyCodexWitnessArgs(test.args)
			if valid != test.valid || version != test.version {
				t.Fatalf("got (%v,%v)", valid, version)
			}
		})
	}
}

func TestNativeProtectionReadyClosedDoneIsEarlyExit(t *testing.T) {
	result := &nativeCodexProtectionResult{done: make(chan struct{}), err: fmt.Errorf("closed")}
	close(result.done)
	if _, category := waitCodexProtectionReadyState(filepath.Join(t.TempDir(), "missing-ready"), result, time.Second); category != "early-exit" {
		t.Fatalf("category=%q", category)
	}
}

func TestNativeDiagnosticSinkConcurrentWrites(t *testing.T) {
	sink := &nativeDiagnosticSink{}
	var writers sync.WaitGroup
	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				sink.Present()
			}
		}
	}()
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 100; j++ {
				if _, err := sink.Write([]byte("diagnostic")); err != nil {
					t.Errorf("sink write: %v", err)
				}
			}
		}()
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	if !sink.Present() {
		t.Fatal("sink did not record concurrent output")
	}
}

func nativeCodexFileIdentity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat protected path %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		t.Fatalf("protected path lacks stable identity: %s", path)
	}
	return uint64(stat.Dev), uint64(stat.Ino)
}

//go:build darwin

package codexauthresource_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/creack/pty"
)

// TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity is the
// credential-free interactive acceptance gate. ACS starts a test-only fixed
// trampoline, which immediately execs the checksum-locked real target and adds
// only literal loopback ChatGPT endpoints after ACS's fixed production
// arguments. The production adapter selects the target's externally sandboxed
// no-prompt mode while ACS remains the sole policy and lifecycle authority.
func TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity(t *testing.T) {
	runNativeInstalledACSLockedCodexFixture(t)
}

func runNativeInstalledACSLockedCodexFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to use an isolated temporary Keychain")
	}
	candidate := os.Getenv("ACS_PROMOTED_BINARY")
	target := os.Getenv("ACS_TEST_CODEX_BINARY")
	archive := os.Getenv("ACS_TEST_CODEX_ARCHIVE")
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(target) || !filepath.IsAbs(archive) {
		t.Fatal("ACS_PROMOTED_BINARY, ACS_TEST_CODEX_BINARY and ACS_TEST_CODEX_ARCHIVE must be absolute")
	}
	assertLockedCodexIdentity(t, archive, target)
	codexauthresource.UseIsolatedTestKeychainForComposition(t)

	root := t.TempDir()
	home, workspace, tools := filepath.Join(root, "home"), filepath.Join(root, "workspace"), filepath.Join(root, "tools")
	for _, directory := range []string{home, workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeNativeSkill(t, filepath.Join(home, ".agents", "skills", "managed-proof"), "managed-proof", "ACS_MANAGED_SKILL_SENTINEL")
	writeNativeSkill(t, filepath.Join(workspace, ".agents", "skills", "project-proof"), "project-proof", "PROJECT_INHERITED_SKILL_SENTINEL")
	hostileMCPMarker := filepath.Join(workspace, "hostile-project-mcp-started")
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".codex", "config.toml"), []byte(
		"[mcp_servers.hostile]\ncommand = \"/bin/sh\"\nargs = [\"-c\", "+strconv.Quote("printf hostile > "+hostileMCPMarker)+"]\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	globalAuth := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("unrelated-global-auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	identities := map[string]string{
		"coding":   "interactive-coding",
		"readonly": "interactive-readonly",
		"recovery": "interactive-recovery",
	}
	configureInstalledCandidateKeychainContext(t, home, tools)
	buildSyntheticLoginTarget(t, filepath.Join(tools, "codex"))
	loginNames := []string{identities["coding"], identities["readonly"], identities["recovery"]}
	for _, identityName := range loginNames {
		if !t.Run("installed ACS synthetic login transaction "+identityName, func(t *testing.T) {
			before := installedSessionSnapshot(t, candidate, home, tools, workspace)
			runInstalledSyntheticLogin(t, candidate, home, tools, workspace, identityName)
			assertInstalledIdentityVisible(t, candidate, home, tools, workspace, identityName)
			assertInstalledIdentityStatus(t, candidate, home, tools, workspace, identityName)
			assertNewRemovedInstalledSessions(t, candidate, home, tools, workspace, before, "codex-auth")
		}) {
			t.FailNow()
		}
	}
	writeNativeCodexProfile(t, home, "coding", identities["coding"], "read-write")
	writeNativeCodexProfile(t, home, "readonly", identities["readonly"], "read-only")
	writeNativeCodexProfile(t, home, "recovery", identities["recovery"], "read-write")
	grantedTarget := filepath.Join(workspace, "locked-codex-target")
	copyLockedTarget(t, target, grantedTarget)
	outside, err := os.MkdirTemp("/tmp", "acs-codex-unrelated-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	outsideSecret, outsideWrite := filepath.Join(outside, "secret"), filepath.Join(outside, "write")
	if err := os.WriteFile(outsideSecret, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	isolationProbe := fmt.Sprintf(`; if cat %s >/dev/null 2>&1; then printf global-auth-read-bad; else printf global-auth-read-denied; fi; if cat %s >/dev/null 2>&1; then printf outside-read-bad; else printf outside-read-denied; fi; if printf bad > %s 2>/dev/null; then printf outside-write-bad; else printf outside-write-denied; fi`, strconv.Quote(globalAuth), strconv.Quote(outsideSecret), strconv.Quote(outsideWrite))
	t.Run("locked Codex preflight and interactive generations remain private while live", func(t *testing.T) {
		before := installedSessionSnapshot(t, candidate, home, tools, workspace)
		fixture := newNativeResponsesFixture(t, "printf codex-native-tool-output"+isolationProbe, home)
		defer fixture.server.Close()
		coordination := nativeCodexPhaseCoordination{
			versionReady:       filepath.Join(workspace, ".acs-codex-version-ready"),
			versionRelease:     filepath.Join(workspace, ".acs-codex-version-release"),
			interactiveReady:   filepath.Join(workspace, ".acs-codex-interactive-ready"),
			interactiveRelease: filepath.Join(workspace, ".acs-codex-interactive-release"),
		}
		buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", filepath.Join(tools, "codex"), coordination)
		fixture.coordination = &coordination
		runInstalledCodexPTY(t, candidate, home, tools, workspace, "coding", fixture, false)
		fixture.assert(t, false)
		assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
		assertNewRemovedInstalledSessions(t, candidate, home, tools, workspace, before, "codex")
	})
	normalDescendantReady := filepath.Join(workspace, ".acs-normal-descendant-ready")
	recoveryDescendantReady := filepath.Join(workspace, ".acs-recovery-descendant-ready")
	codingCommand := "printf codex-native-tool-ok > ./codex-native-write; printf codex-native-tool-output" + isolationProbe
	codingCommand += nativeControlledDescendantCommand(normalDescendantReady)
	for _, test := range []struct {
		name, profile, command, marker, descendantReady string
		wantWrite, wantDescendant                       bool
	}{
		{name: "coding write", profile: "coding", command: codingCommand, marker: "codex-native-write", descendantReady: normalDescendantReady, wantWrite: true, wantDescendant: true},
		{name: "read-only denial", profile: "readonly", command: "printf forbidden > ./codex-native-readonly-write; printf codex-native-tool-output" + isolationProbe, marker: "codex-native-readonly-write", wantWrite: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := installedSessionSnapshot(t, candidate, home, tools, workspace)
			fixture := newNativeResponsesFixture(t, test.command, home)
			fixture.descendantReady = test.descendantReady
			defer fixture.server.Close()
			trampoline := filepath.Join(tools, "codex")
			buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", trampoline)
			t.Logf("harness executable sha256=%s; locked target member sha256=%s", fileSHA256(t, trampoline), fileSHA256(t, grantedTarget))
			runInstalledCodexPTY(t, candidate, home, tools, workspace, test.profile, fixture, false)
			descendantPID := fixture.assert(t, test.wantDescendant)
			if test.wantDescendant {
				assertNativeProcessRemoved(t, descendantPID, "Codex tool descendant survived settlement")
			}
			contents, err := os.ReadFile(filepath.Join(workspace, test.marker))
			if test.wantWrite && (err != nil || string(contents) != "codex-native-tool-ok") {
				t.Fatalf("real Codex shell tool result=%q err=%v", contents, err)
			}
			if !test.wantWrite && !os.IsNotExist(err) {
				t.Fatalf("read-only Codex wrote workspace marker: bytes=%q err=%v", contents, err)
			}
			assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
			assertNewRemovedInstalledSessions(t, candidate, home, tools, workspace, before, "codex")
		})
	}
	t.Run("abrupt ACS termination and public recovery", func(t *testing.T) {
		fixture := newNativeResponsesFixture(t, "printf codex-native-tool-output"+isolationProbe+nativeControlledDescendantCommand(recoveryDescendantReady), home)
		fixture.descendantReady = recoveryDescendantReady
		defer fixture.server.Close()
		buildFixedCodexTrampoline(t, grantedTarget, fixture.server.URL+"/backend-api", filepath.Join(tools, "codex"))
		runInstalledCodexPTY(t, candidate, home, tools, workspace, "recovery", fixture, true)
		descendantPID := fixture.assert(t, true)
		assertNativeProcessRemoved(t, descendantPID, "Codex tool descendant survived abrupt ACS settlement")
		sessions, err := filepath.Glob(filepath.Join(home, ".acs", "sessions", "session-*"))
		if err != nil || len(sessions) != 1 {
			t.Fatalf("abrupt ACS termination retained %d recoverable Sessions", len(sessions))
		}
		recoverable := inspectInstalledRecoverableSession(t, candidate, home, tools, workspace)
		runConcurrentInstalledRecoveries(t, candidate, home, tools, workspace, identities["recovery"], recoverable.id)
		assertInstalledSessionRemoved(t, candidate, home, tools, workspace, recoverable)
		assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
		reuseFixture := newNativeResponsesFixture(t, "printf codex-native-tool-output"+isolationProbe, home)
		defer reuseFixture.server.Close()
		buildFixedCodexTrampoline(t, grantedTarget, reuseFixture.server.URL+"/backend-api", filepath.Join(tools, "codex"))
		runInstalledCodexPTY(t, candidate, home, tools, workspace, "recovery", reuseFixture, false)
		reuseFixture.assert(t, false)
		assertNoNativeSessions(t, filepath.Join(home, ".acs", "sessions"))
	})
	if contents, err := os.ReadFile(globalAuth); err != nil || string(contents) != "unrelated-global-auth" {
		t.Fatal("interactive launch changed global Codex authentication state")
	}
	if _, err := os.Stat(outsideWrite); !os.IsNotExist(err) {
		t.Fatalf("interactive launch wrote unrelated host path: %v", err)
	}
	if _, err := os.Stat(hostileMCPMarker); !os.IsNotExist(err) {
		t.Fatalf("interactive launch started hostile project MCP configuration: %v", err)
	}
}

func nativeControlledDescendantCommand(readyPath string) string {
	quotedReady := strconv.Quote(readyPath)
	return `; /bin/sh -c 'printf "%s" "$$" > "$1"; exec /bin/sleep 30' descendant-sh ` + quotedReady + ` </dev/null >/dev/null 2>&1 & descendant_pid=$!; for descendant_wait in {1..100}; do [ -s ` + quotedReady + ` ] && break; /bin/sleep 0.02; done; printf descendant-pid:%s "$descendant_pid"`
}

func runInstalledSyntheticLogin(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	command := exec.Command(candidate, "codex", "auth", "login", "--name", name)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var output nativeSafeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copyDone) }()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var runErr error
	timedOut := false
	settlementTimedOut := false
	select {
	case runErr = <-wait:
	case <-time.After(20 * time.Second):
		timedOut = true
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case runErr = <-wait:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			select {
			case runErr = <-wait:
			case <-time.After(5 * time.Second):
				settlementTimedOut = true
			}
		}
	}
	_ = master.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("installed ACS synthetic login capture did not drain")
	}
	if settlementTimedOut {
		t.Fatalf("installed ACS synthetic login process group did not settle after corrected Keychain selection; terminal=%q", output.String())
	}
	if timedOut {
		t.Fatalf("installed ACS synthetic login timed out after corrected Keychain selection; terminal=%q; settlement=%v", output.String(), runErr)
	}
	if runErr != nil {
		t.Fatalf("installed ACS synthetic login failed: %v; terminal=%q", runErr, output.String())
	}
	for _, witness := range []string{"synthetic-login-target:started", "synthetic-login-target:auth-written", `Stored Codex authentication identity "` + name + `".`} {
		if !strings.Contains(output.String(), witness) {
			t.Fatalf("installed ACS synthetic login omitted %q; terminal=%q", witness, output.String())
		}
	}
}

func configureInstalledCandidateKeychainContext(t *testing.T, home, tools string) {
	t.Helper()
	parentDefault, parentDefaultOK := queryNativeKeychainSelection(nil, "default-keychain")
	parentSearch, parentSearchOK := queryNativeKeychainSelection(nil, "list-keychains")
	if !parentDefaultOK || !parentSearchOK {
		t.Fatal("isolated parent Keychain selection is unavailable")
	}
	fixtureEnvironment := nativeCandidateEnvironment(home, tools)
	fixtureDefaultBefore, fixtureDefaultBeforeOK := queryNativeKeychainSelection(fixtureEnvironment, "default-keychain")
	fixtureSearchBefore, fixtureSearchBeforeOK := queryNativeKeychainSelection(fixtureEnvironment, "list-keychains")
	t.Logf(
		"synthetic HOME Keychain selection before setup: default-match=%t search-list-match=%t",
		fixtureDefaultBeforeOK && fixtureDefaultBefore == parentDefault,
		fixtureSearchBeforeOK && fixtureSearchBefore == parentSearch,
	)
	keychain := strings.Trim(strings.TrimSpace(parentDefault), `"`)
	if keychain == "" || !filepath.IsAbs(keychain) {
		t.Fatal("isolated default Keychain selection is unavailable")
	}
	if err := os.MkdirAll(filepath.Join(home, "Library", "Preferences"), 0o700); err != nil {
		t.Fatal("prepare synthetic HOME Keychain preferences")
	}
	for _, arguments := range [][]string{
		{"list-keychains", "-d", "user", "-s", keychain},
		{"default-keychain", "-d", "user", "-s", keychain},
	} {
		command := exec.Command("/usr/bin/security", arguments...)
		command.Env = fixtureEnvironment
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatal("configure synthetic HOME to use the disposable Keychain")
		}
	}
	fixtureDefaultAfter, fixtureDefaultAfterOK := queryNativeKeychainSelection(fixtureEnvironment, "default-keychain")
	fixtureSearchAfter, fixtureSearchAfterOK := queryNativeKeychainSelection(fixtureEnvironment, "list-keychains")
	defaultMatches := fixtureDefaultAfterOK && fixtureDefaultAfter == parentDefault
	searchMatches := fixtureSearchAfterOK && fixtureSearchAfter == parentSearch
	t.Logf("synthetic HOME Keychain selection after setup: default-match=%t search-list-match=%t", defaultMatches, searchMatches)
	if !defaultMatches || !searchMatches {
		t.Fatal("synthetic HOME did not select the disposable Keychain")
	}
}

func queryNativeKeychainSelection(environment []string, operation string) (string, bool) {
	command := exec.Command("/usr/bin/security", operation, "-d", "user")
	if environment != nil {
		command.Env = environment
	}
	output, err := command.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}

func nativeCandidateEnvironment(home, tools string) []string {
	return []string{"HOME=" + home, "PATH=" + tools + ":/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=xterm", "COLORTERM=truecolor"}
}

func assertInstalledIdentityVisible(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	command := exec.Command(candidate, "codex", "auth", "list")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed ACS cannot enumerate seeded synthetic identity: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), name) || !strings.Contains(string(output), "synthetic-workspace") {
		t.Fatalf("installed ACS did not enumerate the selected synthetic identity: output=%q", output)
	}
}

func assertInstalledIdentityStatus(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	command := exec.Command(candidate, "codex", "auth", "status", "--name", name)
	command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, tools)
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte(name)) || !bytes.Contains(output, []byte("authenticated")) {
		t.Fatalf("installed ACS named identity status: %v; output=%q", err, output)
	}
}

func runInstalledCodexPTY(t *testing.T, candidate, home, tools, workspace, profile string, fixture *nativeResponsesFixture, crashAfterTool bool) string {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(candidate, "codex", "--profile", profile)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var output nativeSafeCapture
	copyDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copyDone) }()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			select {
			case <-wait:
			case <-time.After(10 * time.Second):
				t.Error("PTY fixture did not reap the installed ACS process")
			}
		}
		_ = master.Close()
		select {
		case <-copyDone:
		case <-time.After(time.Second):
			t.Error("PTY fixture did not drain terminal capture")
		}
	}()
	if fixture.coordination != nil {
		versionCapability := observeNativeCodexPhase(t, candidate, home, tools, workspace, fixture.coordination.versionReady, fixture.coordination.versionRelease, nil)
		fixture.coordination.versionCapability = &versionCapability
		observeNativeCodexPhase(t, candidate, home, tools, workspace, fixture.coordination.interactiveReady, fixture.coordination.interactiveRelease, fixture.coordination.versionCapability)
	}
	select {
	case err := <-wait:
		finished = true
		t.Fatalf("installed ACS or locked target exited before interactive input: %v; terminal=%q", err, output.String())
	case <-time.After(1500 * time.Millisecond):
	}
	if !waitNativeCaptureContainsAfter(&output, 0, "\x1b[1;40r", 10*time.Second) {
		t.Fatalf("real Codex TUI did not render the initial 40-row terminal geometry; terminal=%q", output.String())
	}
	if !waitNativeCaptureStable(&output, 2*time.Second) {
		t.Fatalf("real Codex TUI did not settle its initial 40-row frame; terminal=%q", output.String())
	}
	resizeOffset := output.Len()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 43, Cols: 117}); err != nil {
		t.Fatal(err)
	}
	size, err := pty.GetsizeFull(master)
	if err != nil || size.Rows != 43 || size.Cols != 117 {
		t.Fatalf("resized outer PTY geometry=%v err=%v", size, err)
	}
	if !waitNativeCaptureContainsAfter(&output, resizeOffset, "\x1b[1;43r", 10*time.Second) {
		t.Fatalf("real Codex TUI did not render the resized 43-row terminal geometry; terminal=%q", output.String())
	}
	// Emulate a real terminal paste and let Codex's 120ms paste-burst window
	// settle before sending the separately encoded enhanced Enter key.
	if _, err := master.Write([]byte("\x1b[200~Use the shell tool exactly once as requested by the fixture.\x1b[201~")); err != nil {
		t.Fatalf("write interactive input: %v; terminal=%q", err, output.String())
	}
	if !waitNativeCaptureStable(&output, 2*time.Second) {
		t.Fatalf("real Codex TUI did not settle the bracketed prompt paste; terminal=%q", output.String())
	}
	if _, err := master.Write([]byte("\x1b[13u")); err != nil {
		t.Fatalf("submit interactive input: %v; terminal=%q", err, output.String())
	}
	select {
	case <-fixture.completed:
	case err := <-wait:
		finished = true
		t.Fatalf("installed ACS or locked target exited before completing tool work: %v; terminal=%q", err, output.String())
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("real Codex did not complete two fixture requests; loopback=%s; terminal=%q", fixture.summary(), output.String())
	}
	// A normal exit proves the target rendered the completed assistant turn.
	// The abrupt-settlement case instead stops ACS immediately after the real
	// tool exchange and live-descendant proof; waiting for an otherwise
	// irrelevant repaint makes the kill timing depend on Rosetta throughput.
	if !crashAfterTool && (!waitNativeCaptureContainsAfter(&output, 0, "fixture-complete", 5*time.Second) || !waitNativeCaptureStable(&output, 5*time.Second)) {
		t.Fatalf("real Codex did not finish rendering the completed turn; terminal=%q", output.String())
	}
	fixture.assertLiveDescendant(t)
	if crashAfterTool {
		if err := command.Process.Kill(); err != nil {
			t.Fatalf("abruptly terminate installed ACS after real tool work: %v", err)
		}
		select {
		case err := <-wait:
			finished = true
			if err == nil {
				t.Fatal("abruptly terminated installed ACS reported success")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("abruptly terminated installed ACS was not reaped")
		}
		return output.String()
	}
	time.Sleep(500 * time.Millisecond)
	_, _ = master.Write([]byte{3})
	select {
	case err := <-wait:
		finished = true
		if err != nil {
			t.Fatalf("installed ACS interactive Codex exit: %v; terminal=%q", err, output.String())
		}
	case <-time.After(15 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("interactive Codex did not terminate after PTY cancellation")
	}
	return output.String()
}

func runInstalledCodexRecovery(t *testing.T, candidate, home, tools, workspace, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		command := exec.Command(candidate, "codex", "auth", "recover", "--name", name)
		command.Dir = workspace
		command.Env = nativeCandidateEnvironment(home, tools)
		output, err := command.CombinedOutput()
		if err == nil {
			if !strings.Contains(string(output), `Recovered Codex authentication identity "`+name+`".`) || !strings.Contains(string(output), "disposition:") {
				t.Fatalf("public Codex identity recovery omitted its disposition: output=%q", output)
			}
			return
		}
		if !strings.Contains(string(output), "identity is in use") || time.Now().After(deadline) {
			t.Fatalf("public Codex identity recovery failed: %v; output=%q", err, output)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type installedPublicSession struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Target   string `json:"target"`
	Revision uint64 `json:"revision"`
	Recovery struct {
		Allowed bool `json:"allowed"`
	} `json:"recovery"`
}

type installedRecoverableSession struct {
	id     string
	before map[string]installedPublicSession
}

func installedSessionSnapshot(t *testing.T, candidate, home, tools, workspace string) map[string]installedPublicSession {
	t.Helper()
	command := exec.Command(candidate, "session", "list", "--json")
	command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, tools)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("public Session list failed: %v; output=%q", err, output)
	}
	var listed struct {
		Sessions []installedPublicSession `json:"sessions"`
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		t.Fatalf("decode public Session list: %v; output=%q", err, output)
	}
	result := make(map[string]installedPublicSession, len(listed.Sessions))
	for _, item := range listed.Sessions {
		result[item.ID] = item
	}
	return result
}

func assertNewRemovedInstalledSessions(t *testing.T, candidate, home, tools, workspace string, before map[string]installedPublicSession, target string) {
	t.Helper()
	after := installedSessionSnapshot(t, candidate, home, tools, workspace)
	found := 0
	for id, item := range after {
		if _, existed := before[id]; existed {
			continue
		}
		found++
		if item.State != "removed" || item.Target != target || item.Revision == 0 {
			t.Fatalf("candidate lifecycle row = %+v", item)
		}
	}
	if found == 0 {
		t.Fatalf("candidate %s operation published no durable Session lifecycle row", target)
	}
}

func inspectInstalledRecoverableSession(t *testing.T, candidate, home, tools, workspace string) installedRecoverableSession {
	t.Helper()
	before := installedSessionSnapshot(t, candidate, home, tools, workspace)
	var live []installedPublicSession
	for _, item := range before {
		if item.Target == "codex" && item.State != "removed" && item.Recovery.Allowed {
			live = append(live, item)
		}
	}
	if len(live) != 1 {
		t.Fatalf("live recoverable Codex Sessions = %+v; all Sessions = %+v", live, before)
	}
	item := live[0]
	if item.State != "active" && item.State != "settling" && item.State != "retryable" {
		t.Fatalf("recoverable public Session state = %q; all Sessions = %+v", item.State, before)
	}
	inspect := exec.Command(candidate, "session", "inspect", item.ID, "--json")
	inspect.Dir, inspect.Env = workspace, nativeCandidateEnvironment(home, tools)
	inspected, err := inspect.Output()
	if err != nil || !bytes.Contains(inspected, []byte(`"id":"`+item.ID+`"`)) || bytes.Contains(inspected, []byte("rootToken")) || bytes.Contains(inspected, []byte("challenge")) {
		t.Fatalf("public Session inspect = %q, %v", inspected, err)
	}
	return installedRecoverableSession{id: item.ID, before: before}
}

func runConcurrentInstalledRecoveries(t *testing.T, candidate, home, tools, workspace, name, publicID string) {
	t.Helper()
	start := make(chan struct{})
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 2)
	for _, arguments := range [][]string{{"codex", "auth", "recover", "--name", name}, {"session", "recover", publicID}} {
		arguments := append([]string(nil), arguments...)
		go func() {
			<-start
			command := exec.Command(candidate, arguments...)
			command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, tools)
			output, err := command.CombinedOutput()
			results <- result{output: output, err: err}
		}()
	}
	close(start)
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil && !bytes.Contains(result.output, []byte("in use")) && !bytes.Contains(result.output, []byte("busy")) && !bytes.Contains(result.output, []byte("active")) {
				t.Fatalf("concurrent public recovery failed: %v; output=%q", result.err, result.output)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("concurrent public recovery deadlocked")
		}
	}
	runInstalledCodexRecovery(t, candidate, home, tools, workspace, name)
	deadline := time.Now().Add(10 * time.Second)
	for {
		command := exec.Command(candidate, "session", "recover", publicID)
		command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, tools)
		output, err := command.CombinedOutput()
		if err == nil && bytes.Contains(output, []byte("removed")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("public Session recovery did not converge: %v; output=%q", err, output)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func assertInstalledSessionRemoved(t *testing.T, candidate, home, tools, workspace string, recoverable installedRecoverableSession) {
	t.Helper()
	command := exec.Command(candidate, "session", "inspect", recoverable.id, "--json")
	command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, tools)
	output, err := command.Output()
	if err != nil || !bytes.Contains(output, []byte(`"state":"removed"`)) || bytes.Contains(output, []byte("rootToken")) || bytes.Contains(output, []byte("challenge")) {
		t.Fatalf("removed public Session = %q, %v", output, err)
	}
	after := installedSessionSnapshot(t, candidate, home, tools, workspace)
	if item, exists := after[recoverable.id]; !exists || item.State != "removed" {
		t.Fatalf("recovered Session did not remain as a removed public row: %+v", item)
	}
	for id, item := range recoverable.before {
		if id == recoverable.id || item.State != "removed" {
			continue
		}
		if preserved, exists := after[id]; !exists || preserved.State != "removed" {
			t.Fatalf("old removed Session row %s was not preserved: %+v", id, preserved)
		}
	}
}

func assertNativeProcessRemoved(t *testing.T, pid int, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && syscall.Kill(pid, 0) == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("%s: pid=%d err=%v", message, pid, err)
	}
}

func waitNativeCaptureStable(capture *nativeSafeCapture, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	last := -1
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		length := capture.Len()
		if length != last {
			last = length
			stableSince = time.Now()
		} else if time.Since(stableSince) >= 150*time.Millisecond {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func waitNativeCaptureContainsAfter(capture *nativeSafeCapture, offset int, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		contents := capture.String()
		if offset <= len(contents) && strings.Contains(contents[offset:], needle) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

type nativeSafeCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (capture *nativeSafeCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Write(contents)
}

func (capture *nativeSafeCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String()
}

func (capture *nativeSafeCapture) Len() int {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.Len()
}

type nativeResponsesFixture struct {
	server                *httptest.Server
	completed             chan struct{}
	mu                    sync.Mutex
	requests              int
	bodies                []string
	headers               []http.Header
	sessionObservationErr string
	observations          []nativeRequestObservation
	websocketFallbacks    int
	modelRequests         int
	protocolErr           string
	preexistingHomes      map[string]struct{}
	descendantReady       string
	liveDescendantPID     int
	coordination          *nativeCodexPhaseCoordination
}

// nativeCodexPhaseCoordination is intentionally fixture-only.  Its literal
// paths let the host observe the Session selected by ACS without providing any
// private capability contents or recovery proof to the locked target.
type nativeCodexPhaseCoordination struct {
	versionReady, versionRelease, interactiveReady, interactiveRelease string
	versionCapability                                                  *nativeCodexCapability
}

type nativeCodexCapability struct {
	ID, RootName, Challenge string
	Generation              uint64
}

func observeNativeCodexPhase(t *testing.T, candidate, home, tools, workspace, ready, release string, previous *nativeCodexCapability) nativeCodexCapability {
	t.Helper()
	if !waitForNativeCodexMarker(ready, 15*time.Second) {
		t.Fatalf("locked Codex phase did not become ready: %s", filepath.Base(ready))
	}
	capability := readLiveNativeCodexCapability(t, home)
	phaseHome, err := os.ReadFile(ready)
	wantHome := filepath.Join(home, ".acs", "sessions", capability.RootName, "home")
	if err != nil || filepath.Clean(strings.TrimSpace(string(phaseHome))) != wantHome {
		t.Fatalf("locked Codex phase HOME is not bound to its private capability root: err=%v", err)
	}
	if previous != nil && (capability.ID != previous.ID || capability.RootName != previous.RootName || capability.Generation <= previous.Generation || capability.Challenge == previous.Challenge) {
		t.Fatalf("locked Codex capability generation was not fresh across phases")
	}
	root := filepath.Join(home, ".acs", "sessions", capability.RootName)
	if _, err := os.Stat(filepath.Join(root, ".acs-cleanup-proof-v1")); !os.IsNotExist(err) {
		t.Fatalf("live locked Codex phase retained a cleanup proof: %v", err)
	}
	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recover := exec.CommandContext(context, candidate, "session", "recover", capability.ID, "--json")
	recover.Dir, recover.Env = workspace, nativeCandidateEnvironment(home, tools)
	output, err := recover.CombinedOutput()
	if context.Err() != nil {
		t.Fatal("public recovery did not settle while locked Codex was live")
	}
	var result struct {
		Outcome string `json:"outcome"`
	}
	if err == nil || json.Unmarshal(output, &result) != nil || result.Outcome != "busy" {
		t.Fatal("public recovery did not report busy for a live locked Codex Session")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("public recovery did not preserve the live locked Codex Session root: %v", err)
	}
	if err := os.WriteFile(release, []byte("release\n"), 0o600); err != nil {
		t.Fatalf("release locked Codex phase: %v", err)
	}
	return capability
}

func waitForNativeCodexMarker(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func readLiveNativeCodexCapability(t *testing.T, home string) nativeCodexCapability {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(home, ".acs", "session-operations-v1", "capabilities", "*.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("live locked Codex capability entries=%d err=%v", len(entries), err)
	}
	var capability nativeCodexCapability
	contents, err := os.ReadFile(entries[0])
	if err != nil || json.Unmarshal(contents, &capability) != nil || capability.ID == "" || capability.RootName == "" || capability.Generation == 0 || capability.Challenge == "" {
		t.Fatalf("read live locked Codex capability: %v", err)
	}
	return capability
}

type nativeRequestObservation struct {
	method, path                 string
	hasAuthorization, hasAccount bool
}

func newNativeResponsesFixture(t *testing.T, shellCommand, launcherHome string) *nativeResponsesFixture {
	t.Helper()
	fixture := &nativeResponsesFixture{completed: make(chan struct{}), preexistingHomes: make(map[string]struct{})}
	for _, home := range nativeSessionHomes(launcherHome) {
		fixture.preexistingHomes[home] = struct{}{}
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		fixture.observations = append(fixture.observations, nativeRequestObservation{
			method: request.Method, path: request.URL.Path,
			hasAuthorization: request.Header.Get("Authorization") != "",
			hasAccount:       request.Header.Get("ChatGPT-Account-ID") != "",
		})
		if fixture.protocolErr == "" && (request.Header.Get("Authorization") != "Bearer synthetic-access" || request.Header.Get("ChatGPT-Account-ID") != "synthetic-workspace") {
			fixture.protocolErr = "loopback request did not retain the exact named identity headers"
		}
		fixture.mu.Unlock()
		switch request.URL.Path {
		case "/backend-api/codex/models":
			if request.Method != http.MethodGet {
				fixture.rejectProtocol(response, "models endpoint used a non-GET method")
				return
			}
			fixture.mu.Lock()
			fixture.modelRequests++
			fixture.mu.Unlock()
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"models":[]}`)
			return
		case "/backend-api/codex/responses":
			if request.Method == http.MethodGet && strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
				fixture.mu.Lock()
				fixture.websocketFallbacks++
				fixture.mu.Unlock()
				response.Header().Set("Upgrade", "websocket")
				response.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			if request.Method != http.MethodPost {
				fixture.rejectProtocol(response, "Responses endpoint used neither WebSocket upgrade nor POST")
				return
			}
		case "/backend-api/wham/rate-limit-reset-credits", "/backend-api/wham/usage", "/backend-api/wham/settings/user":
			if request.Method != http.MethodGet {
				fixture.rejectProtocol(response, "usage endpoint used a non-GET method")
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{}`)
			return
		case "/backend-api/codex/analytics-events/events":
			if request.Method != http.MethodPost {
				fixture.rejectProtocol(response, "analytics endpoint used a non-POST method")
				return
			}
			response.WriteHeader(http.StatusNoContent)
			return
		default:
			fixture.rejectProtocol(response, "locked target requested an unexpected loopback path")
			return
		}
		body, err := decodeNativeResponsesBody(request.Body, request.Header.Get("Content-Encoding"))
		if err != nil {
			fixture.rejectProtocol(response, err.Error())
			return
		}
		fixture.mu.Lock()
		fixture.requests++
		index := fixture.requests
		fixture.bodies = append(fixture.bodies, body)
		fixture.headers = append(fixture.headers, request.Header.Clone())
		if index == 2 {
			fixture.sessionObservationErr = observeNativeSessionProjection(launcherHome, fixture.preexistingHomes)
		}
		fixture.mu.Unlock()
		response.Header().Set("Content-Type", "text/event-stream")
		if index == 1 {
			arguments, _ := json.Marshal(map[string]any{"command": shellCommand, "timeout_ms": 5000})
			writeSSE(response,
				map[string]any{"type": "response.created", "response": map[string]any{"id": "resp-1"}},
				map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "function_call", "call_id": "acs-call-1", "name": "shell_command", "arguments": string(arguments)}},
				completedEvent("resp-1"),
			)
			return
		}
		writeSSE(response,
			map[string]any{
				"type": "response.output_item.done",
				"item": map[string]any{
					"type": "message", "role": "assistant", "id": "msg-1",
					"content": []map[string]string{{"type": "output_text", "text": "fixture-complete"}},
				},
			},
			completedEvent("resp-2"),
		)
		if index == 2 {
			close(fixture.completed)
		}
	}))
	return fixture
}

func TestNativeResponsesFixtureSeparatesModelDiscoveryAndWebSocketFallback(t *testing.T) {
	fixture := newNativeResponsesFixture(t, "printf fixture", t.TempDir())
	defer fixture.server.Close()
	for _, test := range []struct {
		name, path, upgrade string
		wantStatus          int
		wantBody            string
	}{
		{name: "model discovery", path: "/backend-api/codex/models", wantStatus: http.StatusOK, wantBody: `{"models":[]}`},
		{name: "Responses WebSocket fallback", path: "/backend-api/codex/responses", upgrade: "websocket", wantStatus: http.StatusUpgradeRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, fixture.server.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer synthetic-access")
			request.Header.Set("ChatGPT-Account-ID", "synthetic-workspace")
			if test.upgrade != "" {
				request.Header.Set("Connection", "upgrade")
				request.Header.Set("Upgrade", test.upgrade)
			}
			response, err := fixture.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read fixture response = (%v, %v)", readErr, closeErr)
			}
			if response.StatusCode != test.wantStatus || (test.wantBody != "" && string(body) != test.wantBody) {
				t.Fatalf("fixture response = status %d body %q", response.StatusCode, body)
			}
		})
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.protocolErr != "" || fixture.requests != 0 || fixture.modelRequests != 1 || fixture.websocketFallbacks != 1 {
		t.Fatalf("fixture routing = protocol=%q responses=%d models=%d fallbacks=%d", fixture.protocolErr, fixture.requests, fixture.modelRequests, fixture.websocketFallbacks)
	}
}

func (fixture *nativeResponsesFixture) rejectProtocol(response http.ResponseWriter, message string) {
	fixture.mu.Lock()
	if fixture.protocolErr == "" {
		fixture.protocolErr = message
	}
	fixture.mu.Unlock()
	http.Error(response, "fixture protocol rejected", http.StatusBadRequest)
}

func (fixture *nativeResponsesFixture) assert(t *testing.T, wantDescendant bool) int {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.protocolErr != "" {
		t.Fatalf("fixture protocol error: %s; loopback=%s", fixture.protocolErr, fixture.summaryLocked())
	}
	if fixture.requests != 2 || len(fixture.bodies) != 2 {
		t.Fatalf("responses requests=%d; loopback=%s", fixture.requests, fixture.summaryLocked())
	}
	if fixture.websocketFallbacks != 1 {
		t.Fatalf("Responses WebSocket fallbacks=%d, want one; loopback=%s", fixture.websocketFallbacks, fixture.summaryLocked())
	}
	if fixture.modelRequests < 1 {
		t.Fatalf("authenticated model requests=%d, want at least one; loopback=%s", fixture.modelRequests, fixture.summaryLocked())
	}
	if fixture.sessionObservationErr != "" {
		t.Fatal(fixture.sessionObservationErr)
	}
	for _, headers := range fixture.headers {
		if headers.Get("Authorization") != "Bearer synthetic-access" || headers.Get("ChatGPT-Account-ID") != "synthetic-workspace" {
			t.Fatalf("named identity headers were not preserved: authorization=%q account=%q", headers.Get("Authorization"), headers.Get("ChatGPT-Account-ID"))
		}
	}
	for _, sentinel := range []string{"ACS_MANAGED_SKILL_SENTINEL", "PROJECT_INHERITED_SKILL_SENTINEL"} {
		if !strings.Contains(fixture.bodies[0], sentinel) {
			t.Fatalf("first request omitted Skill discovery sentinel %q", sentinel)
		}
	}
	toolOutput, err := nativeFunctionCallOutput(fixture.bodies[1], "acs-call-1")
	if err != nil {
		t.Fatalf("second request tool output: %v", err)
	}
	for _, sentinel := range []string{"codex-native-tool-output", "global-auth-read-denied", "outside-read-denied", "outside-write-denied"} {
		if !strings.Contains(toolOutput, sentinel) {
			t.Fatalf("second request omitted real shell result %q", sentinel)
		}
	}
	if strings.Contains(toolOutput, "global-auth-read-bad") || strings.Contains(toolOutput, "outside-read-bad") || strings.Contains(toolOutput, "outside-write-bad") {
		t.Fatal("matching function output reports an isolation escape")
	}
	if !wantDescendant {
		return 0
	}
	match := regexp.MustCompile(`descendant-pid:(\d+)`).FindStringSubmatch(toolOutput)
	if len(match) != 2 {
		t.Fatal("second request omitted descendant process identity")
	}
	pid, err := strconv.Atoi(match[1])
	if err != nil || pid < 2 {
		t.Fatal("second request contained invalid descendant process identity")
	}
	if fixture.liveDescendantPID != pid {
		t.Fatalf("controlled descendant pid=%d was not the live pre-teardown descendant pid=%d", pid, fixture.liveDescendantPID)
	}
	return pid
}

func (fixture *nativeResponsesFixture) assertLiveDescendant(t *testing.T) {
	t.Helper()
	if fixture.descendantReady == "" {
		return
	}
	fixture.mu.Lock()
	if len(fixture.bodies) != 2 {
		fixture.mu.Unlock()
		t.Fatal("cannot verify controlled descendant before the completed tool exchange")
	}
	toolOutput, err := nativeFunctionCallOutput(fixture.bodies[1], "acs-call-1")
	fixture.mu.Unlock()
	if err != nil {
		t.Fatalf("controlled descendant output: %v", err)
	}
	match := regexp.MustCompile(`descendant-pid:(\d+)`).FindStringSubmatch(toolOutput)
	if len(match) != 2 {
		t.Fatal("controlled descendant did not publish its process identity")
	}
	pid, err := strconv.Atoi(match[1])
	if err != nil || pid < 2 {
		t.Fatal("controlled descendant published an invalid process identity")
	}
	ready, err := os.ReadFile(fixture.descendantReady)
	if err != nil || strings.TrimSpace(string(ready)) != strconv.Itoa(pid) {
		t.Fatalf("controlled descendant readiness=%q err=%v, want child pid %d", ready, err, pid)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("controlled descendant pid %d was not live before teardown: %v", pid, err)
	}
	command, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil || filepath.Base(strings.TrimSpace(string(command))) != "sleep" {
		t.Fatalf("controlled descendant pid %d identity=%q err=%v, want sleep", pid, command, err)
	}
	fixture.mu.Lock()
	fixture.liveDescendantPID = pid
	fixture.mu.Unlock()
}

func (fixture *nativeResponsesFixture) summaryLocked() string {
	parts := make([]string, 0, len(fixture.observations))
	for _, observation := range fixture.observations {
		parts = append(parts, fmt.Sprintf("%s %q auth=%t account=%t", observation.method, observation.path, observation.hasAuthorization, observation.hasAccount))
	}
	return strings.Join(parts, "; ")
}

func (fixture *nativeResponsesFixture) summary() string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.summaryLocked()
}

func nativeSessionHomes(launcherHome string) []string {
	homes, _ := filepath.Glob(filepath.Join(launcherHome, ".acs", "sessions", "session-*", "home"))
	return homes
}

func observeNativeSessionProjection(launcherHome string, preexisting map[string]struct{}) string {
	var sessionHomes []string
	for _, home := range nativeSessionHomes(launcherHome) {
		if _, existed := preexisting[home]; !existed {
			sessionHomes = append(sessionHomes, home)
		}
	}
	if len(sessionHomes) != 1 {
		return "live target did not retain exactly one private Session HOME"
	}
	sessionHome := sessionHomes[0]
	var rolloutPath string
	err := filepath.WalkDir(filepath.Join(sessionHome, ".codex", "sessions"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "rollout-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			rolloutPath = path
		}
		return nil
	})
	if err != nil || rolloutPath == "" {
		return "locked Codex private rollout was not observable while the Session was retained"
	}
	info, err := os.Stat(rolloutPath)
	if err != nil || info.Size() == 0 {
		return "locked Codex private rollout was empty or unavailable"
	}
	relativeRollout, err := filepath.Rel(sessionHome, rolloutPath)
	if err != nil {
		return "locked Codex private rollout path was invalid"
	}
	if _, err := os.Stat(filepath.Join(launcherHome, relativeRollout)); !os.IsNotExist(err) {
		return "locked Codex private rollout reached the launcher HOME"
	}
	return ""
}

func completedEvent(id string) map[string]any {
	return map[string]any{"type": "response.completed", "response": map[string]any{"id": id, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}}
}

func writeSSE(writer io.Writer, events ...map[string]any) {
	for _, event := range events {
		encoded, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(writer, "data: %s\n\n", encoded)
	}
}

func buildFixedCodexTrampoline(t *testing.T, target, baseURL, destination string, coordination ...nativeCodexPhaseCoordination) {
	t.Helper()
	source := filepath.Join(filepath.Dir(destination), "codex-trampoline.c")
	openAIOverride := fmt.Sprintf("openai_base_url=%q", baseURL+"/codex")
	chatGPTOverride := fmt.Sprintf("chatgpt_base_url=%q", baseURL)
	var versionReady, versionRelease, interactiveReady, interactiveRelease string
	if len(coordination) > 0 {
		versionReady, versionRelease = coordination[0].versionReady, coordination[0].versionRelease
		interactiveReady, interactiveRelease = coordination[0].interactiveReady, coordination[0].interactiveRelease
	}
	program := fmt.Sprintf(`#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int ready_and_wait(const char *ready, const char *release) {
  if (ready[0] == '\0') return 0;
  const char *home = getenv("HOME");
  if (!home) return 122;
  size_t temporary_length = strlen(ready) + 12;
  char *temporary = malloc(temporary_length);
  if (!temporary) return 123;
  if (snprintf(temporary, temporary_length, "%%s.tmp-XXXXXX", ready) < 0) return 123;
  int fd = mkstemp(temporary);
  if (fd < 0) return 123;
  if (fchmod(fd, 0600) != 0) { close(fd); unlink(temporary); return 124; }
  size_t length = strlen(home);
  if (write(fd, home, length) != (ssize_t)length || close(fd) != 0) { unlink(temporary); return 124; }
  if (rename(temporary, ready) != 0) { unlink(temporary); return 124; }
  struct stat info;
  for (int attempt = 0; attempt < 1500; attempt++) {
    if (stat(release, &info) == 0) return 0;
    usleep(20000);
  }
  return 125;
}
int main(int argc, char **argv) {
  char **next = calloc((size_t)argc + 5, sizeof(char *));
  if (!next) return 120;
  next[0] = %s;
  int version = 0;
  for (int i = 1; i < argc; i++) {
    next[i] = argv[i];
    if (strcmp(argv[i], "--version") == 0) version = 1;
	}
	if (!version) {
		next[argc] = "-c";
    next[argc + 1] = %s;
		next[argc + 2] = "-c";
		next[argc + 3] = %s;
	}
	if (ready_and_wait(version ? %s : %s, version ? %s : %s) != 0) return 126;
  execv(next[0], next);
  return 121;
}
`, strconv.Quote(target), strconv.Quote(openAIOverride), strconv.Quote(chatGPTOverride), strconv.Quote(versionReady), strconv.Quote(interactiveReady), strconv.Quote(versionRelease), strconv.Quote(interactiveRelease))
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.CreateTemp(filepath.Dir(destination), ".codex-trampoline-*")
	if err != nil {
		t.Fatal("prepare fixed Codex trampoline replacement")
	}
	replacementPath := replacement.Name()
	if err := replacement.Close(); err != nil {
		t.Fatal("prepare fixed Codex trampoline replacement")
	}
	defer os.Remove(replacementPath)
	if output, err := exec.Command("/usr/bin/clang", "-Os", source, "-o", replacementPath).CombinedOutput(); err != nil {
		t.Fatalf("compile fixed Codex trampoline: %v: %s", err, output)
	}
	if err := os.Chmod(replacementPath, 0o500); err != nil {
		t.Fatal("secure fixed Codex trampoline replacement")
	}
	if err := os.Rename(replacementPath, destination); err != nil {
		t.Fatal("atomically install fixed Codex trampoline replacement")
	}
}

func buildSyntheticLoginTarget(t *testing.T, destination string) {
	t.Helper()
	auth := compositionAuth(t)
	encoded := make([]string, len(auth))
	for index, value := range auth {
		encoded[index] = strconv.Itoa(int(value))
	}
	source := filepath.Join(t.TempDir(), "synthetic-login.c")
	program := `#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static const unsigned char auth[] = {` + strings.Join(encoded, ",") + `};
int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--version") == 0) { puts("codex-cli 0.149.1"); return 0; }
  }
  fputs("synthetic-login-target:started\n", stderr);
  fflush(stderr);
  const char *home = getenv("HOME");
  if (!home) return 10;
  char path[4096];
  if (snprintf(path, sizeof(path), "%s/.codex/auth.json", home) <= 0) return 11;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return 12;
  if (write(fd, auth, sizeof(auth)) != sizeof(auth) || fsync(fd) != 0 || close(fd) != 0) return 13;
  fputs("synthetic-login-target:auth-written\n", stderr);
  fflush(stderr);
  return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/clang", "-Os", source, "-o", destination).CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic login target: %v: %s", err, output)
	}
}

func writeNativeSkill(t *testing.T, directory, name, sentinel string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := "---\nname: " + name + "\ndescription: " + sentinel + "\n---\nUse this Skill only as native discovery evidence.\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeNativeCodexProfile(t *testing.T, home, profileName, authRef, access string) {
	t.Helper()
	profiles := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	document := `{"version":3,"name":` + strconv.Quote(profileName) + `,"common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"managed-proof"}]},"workspace":{"version":1,"selection":{"access":` + strconv.Quote(access) + `}}},"overlays":{"codex":{"version":1,"authRef":` + strconv.Quote(authRef) + `}}}`
	if err := os.WriteFile(filepath.Join(profiles, profileName+".json"), []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertLockedCodexIdentity(t *testing.T, archivePath, installedPath string) {
	t.Helper()
	const want = "ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405"
	if runtime.GOARCH != "arm64" || fileSHA256(t, archivePath) != want {
		t.Fatal("Codex release archive does not match the reviewed architecture lock")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != "codex-aarch64-apple-darwin" {
		t.Fatal("locked archive member is not the expected regular target")
	}
	member, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("locked archive contains more than one member")
	}
	installed, err := os.ReadFile(installedPath)
	if err != nil || !bytes.Equal(member, installed) {
		t.Fatal("installed Codex bytes differ from the independently extracted locked member")
	}
	if output, err := exec.Command(installedPath, "--version").Output(); err != nil || strings.TrimSpace(string(output)) != "codex-cli 0.149.1" {
		t.Fatal("installed Codex member reports an unsupported version")
	}
}

func copyLockedTarget(t *testing.T, source, destination string) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, contents, 0o500); err != nil {
		t.Fatal(err)
	}
	if fileSHA256(t, source) != fileSHA256(t, destination) {
		t.Fatal("granted fixture target differs from installed locked target")
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func assertNoNativeSessions(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("interactive launch retained Session %q", entry.Name())
		}
	}
}

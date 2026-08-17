//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestPromotedArtifactReportsItsVersionAndCreatesAnEmptyProfileThroughAPTY(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)

	version := exec.Command(binary, "version")
	version.Env = promotedEnvironment(home, os.Getenv("PATH"))
	versionOutput, err := version.CombinedOutput()
	if err != nil {
		t.Fatalf("installed acs version failed: %v", err)
	}
	if got, want := string(versionOutput), "acs "+promotedVersion(t)+"\n"; got != want {
		t.Fatal("installed acs version output did not match the supplied candidate")
	}

	result := runPromotedPTY(t, binary, home, "promoted-empty", func(t *testing.T, terminal io.Writer, capture *safeCapture) {
		waitForOutput(t, capture, `Create Profile "promoted-empty"`)
		writePTY(t, terminal, "\x1b[B", "\r")
		waitForOutput(t, capture, "Create an empty Profile?")
		writePTY(t, terminal, "y")
	})
	if result.exitCode != 0 {
		t.Fatalf("empty Profile creation exited %d", result.exitCode)
	}
	if strings.Count(result.output, "\x1b[?1049h") != 1 || strings.Count(result.output, "\x1b[?1049l") != 1 {
		t.Fatal("installed builder did not enter and exit alternate screen exactly once")
	}

	profilePath := filepath.Join(home, ".acs", "profiles", "promoted-empty.json")
	contents, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("created Profile is unavailable: %v", err)
	}
	for _, fragment := range []string{`"version": 2`, `"name": "promoted-empty"`, `"target": "devin"`, `"skills"`, `"selection": []`} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Errorf("created Profile omits %s", fragment)
		}
	}
	assertPermissions(t, profilePath, 0o600)
	assertPermissions(t, filepath.Dir(profilePath), 0o700)
	entries, err := os.ReadDir(filepath.Dir(profilePath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "promoted-empty.json" {
		t.Fatalf("atomic Profile persistence left unexpected entries: %v", entries)
	}
}

func TestPromotedArtifactRestoresThePTYForOrdinaryAndChangedDraftCancellation(t *testing.T) {
	binary := promotedBinary(t)

	t.Run("ordinary cancellation", func(t *testing.T) {
		home := realTemporaryDirectory(t)
		result := runPromotedPTY(t, binary, home, "ordinary-cancel", func(t *testing.T, terminal io.Writer, capture *safeCapture) {
			waitForOutput(t, capture, `Create Profile "ordinary-cancel"`)
			writePTY(t, terminal, "\x1b")
		})
		assertCancelledPTY(t, result)
		assertProfileAbsent(t, home, "ordinary-cancel")
	})

	t.Run("changed draft cancellation", func(t *testing.T) {
		home := realTemporaryDirectory(t)
		writeSkillBundle(t, home, "review")
		result := runPromotedPTY(t, binary, home, "changed-cancel", func(t *testing.T, terminal io.Writer, capture *safeCapture) {
			waitForOutput(t, capture, `Create Profile "changed-cancel"`)
			writePTY(t, terminal, "\r")
			waitForOutput(t, capture, "review")
			writePTY(t, terminal, " ", "\x1b[D")
			waitForOutput(t, capture, `Create Profile "changed-cancel"`)
			writePTY(t, terminal, "\x03")
			waitForOutput(t, capture, "Discard changes?")
			writePTY(t, terminal, "n")
			waitForOutput(t, capture, `Create Profile "changed-cancel"`)
			writePTY(t, terminal, "\x03")
			waitForOutput(t, capture, "Discard changes?")
			writePTY(t, terminal, "y")
		})
		assertCancelledPTY(t, result)
		assertProfileAbsent(t, home, "changed-cancel")
	})
}

func TestPromotedArtifactSandboxContract(t *testing.T) {
	_ = promotedBinary(t)
	contracts := map[string]func(*testing.T){
		"unavailable": assertPromotedArtifactFailsClosedWithoutABackend,
		"available": func(t *testing.T) {
			assertPromotedArtifactDryRunAndFakeDevinLaunchPreserveTheRuntimeBoundary(t)
			assertPromotedArtifactForwardsSignalsAndPreservesConcurrentSessionLeases(t)
		},
	}
	capability := promotedSandboxCapability(t)
	contract, ok := contracts[capability]
	if !ok {
		t.Fatalf("ACS_PROMOTED_SANDBOX_BACKEND = %q, want unavailable or available", capability)
	}
	t.Run(capability, contract)
}

func assertPromotedArtifactFailsClosedWithoutABackend(t *testing.T) {
	binary := promotedBinary(t)
	home, basePath := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	toolsDirectory := filepath.Join(fixtureRoot, "private-tools")
	if err := os.Mkdir(toolsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	targetMarker := filepath.Join(fixtureRoot, "target-started")
	writeFakeDevin(t, filepath.Join(toolsDirectory, "devin"), `#!/bin/sh
touch ./target-started
printf 'PRIVATE_BACKEND_OUTPUT\n'
printf 'PRIVATE_POLICY_TEXT\n' >&2
exit 23
`)

	launch := exec.Command(binary, "devin", "--profile", "reviews")
	launch.Env = append(promotedEnvironment(home, toolsDirectory+string(os.PathListSeparator)+basePath), "PRIVATE_ENVIRONMENT_VALUE=DO_NOT_LEAK")
	launch.Dir = fixtureRoot
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	launch.Stdout = &stdout
	launch.Stderr = &stderr
	err := launch.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 1 {
		t.Fatalf("promoted launch error = %v, want exit 1", err)
	}
	if stdout.Len() != 0 {
		t.Fatal("backend-unavailable launch wrote stdout")
	}
	wantDiagnostic := "acs: launch Profile \"reviews\": backend_unavailable: process sandbox unavailable: required system backend is unavailable; ACS will not start Devin without the required sandbox\n"
	if got := stderr.String(); got != wantDiagnostic {
		t.Fatal("backend-unavailable diagnostic did not match the stable safe failure")
	}
	if _, err := os.Stat(targetMarker); !os.IsNotExist(err) {
		t.Fatalf("fake Devin started without a sandbox backend: %v", err)
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactDryRunAndFakeDevinLaunchPreserveTheRuntimeBoundary(t *testing.T) {
	binary := promotedBinary(t)
	home, basePath := prepareRuntimeHome(t)

	fixtureRoot := realTemporaryDirectory(t)
	toolsDirectory := filepath.Join(fixtureRoot, "tools")
	if err := os.Mkdir(toolsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(fixtureRoot, "events")
	writeFakeDevin(t, filepath.Join(toolsDirectory, "devin"), `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf 'preflight-skills:%s\n' "$HOME" >> ./events
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'preflight-auth:%s\n' "$HOME" >> ./events
  [ -f "$HOME/.local/share/devin/credentials.toml" ] || exit 65
  if [ -f ./auth-fail ]; then
    printf 'token=DO_NOT_LEAK\n' >&2
    exit 66
  fi
  printf 'Logged in (fixture).\n'
  exit 0
fi
printf 'launch:%s:%s\n' "$HOME" "$#" >> ./events
IFS= read -r line
printf 'fake stdout:%s\n' "$line"
printf 'fake stderr:%s\n' "$line" >&2
exit 23
`)
	path := toolsDirectory + string(os.PathListSeparator) + basePath
	environment := promotedEnvironment(home, path)

	dryRun := exec.Command(binary, "devin", "--profile", "reviews", "--dry-run")
	dryRun.Env = environment
	dryRun.Dir = fixtureRoot
	dryOutput, err := dryRun.CombinedOutput()
	if err != nil {
		t.Fatalf("promoted dry run failed: %v", err)
	}
	for _, want := range []string{"Dry run for Profile \"reviews\"", "review [devin-config]", "No Session was created and Devin was not started."} {
		if !strings.Contains(string(dryOutput), want) {
			t.Errorf("dry-run output omits %q", want)
		}
	}
	if _, err := os.Stat(eventsPath); !os.IsNotExist(err) {
		t.Fatalf("dry run invoked fake Devin: %v", err)
	}
	assertNoSessions(t, home)

	launch := exec.Command(binary, "devin", "--profile", "reviews")
	launch.Env = environment
	launch.Dir = fixtureRoot
	launch.Stdin = strings.NewReader("attached input\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	launch.Stdout = &stdout
	launch.Stderr = &stderr
	err = launch.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 23 {
		t.Fatalf("promoted launch error = %v, want child exit 23", err)
	}
	if got, want := stdout.String(), "fake stdout:attached input\n"; got != want {
		t.Error("attached stdout did not preserve target output")
	}
	if got, want := stderr.String(), "fake stderr:attached input\n"; got != want {
		t.Error("attached stderr did not preserve target output")
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(events)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "preflight-skills:") || !strings.HasPrefix(lines[1], "preflight-auth:") || !strings.HasPrefix(lines[2], "launch:") {
		t.Fatal("fake Devin did not record the expected preflight and launch order")
	}
	for _, line := range lines {
		if !strings.Contains(line, filepath.Join(home, ".acs", "sessions")+string(filepath.Separator)+"session-") {
			t.Error("fake Devin did not use an isolated Session home")
		}
	}
	assertNoSessions(t, home)

	t.Run("authentication failure", func(t *testing.T) {
		if err := os.Remove(eventsPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixtureRoot, "auth-fail"), []byte("fail\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		failed := exec.Command(binary, "devin", "--profile", "reviews")
		failed.Env = environment
		failed.Dir = fixtureRoot
		output, err := failed.CombinedOutput()
		if err == nil {
			t.Fatal("promoted launch accepted failed authentication")
		}
		if !strings.Contains(string(output), "authentication probe failed") {
			t.Error("authentication failure did not identify the expected stable category")
		}
		if strings.Contains(string(output), "DO_NOT_LEAK") {
			t.Fatal("authentication failure leaked subprocess output")
		}
		events, readErr := os.ReadFile(eventsPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(events), "launch:") {
			t.Fatal("fake Devin launched after failed authentication")
		}
		assertNoSessions(t, home)
	})
}

func assertPromotedArtifactForwardsSignalsAndPreservesConcurrentSessionLeases(t *testing.T) {
	binary := promotedBinary(t)

	t.Run("signal forwarding", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			signal     os.Signal
			wantExit   int
			wantRecord string
		}{
			{name: "termination", signal: syscall.SIGTERM, wantExit: 42, wantRecord: "SIGTERM\n"},
		} {
			t.Run(test.name, func(t *testing.T) {
				home, path := prepareRuntimeHome(t)
				fixtureRoot := realTemporaryDirectory(t)
				toolsDirectory := filepath.Join(fixtureRoot, "tools")
				if err := os.Mkdir(toolsDirectory, 0o700); err != nil {
					t.Fatal(err)
				}
				readyPath := filepath.Join(fixtureRoot, "ready")
				recordPath := filepath.Join(fixtureRoot, "record")
				writeFakeDevin(t, filepath.Join(toolsDirectory, "devin"), successfulFakeDevin(`
trap 'printf "SIGTERM\n" > ./record; exit 42' TERM
touch ./ready
while :; do sleep 1; done
`))
				environment := promotedEnvironment(home, toolsDirectory+string(os.PathListSeparator)+path)
				command := exec.Command(binary, "devin", "--profile", "reviews")
				command.Env = environment
				command.Dir = fixtureRoot
				var output bytes.Buffer
				command.Stdout, command.Stderr = &output, &output
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = command.Process.Kill() })
				waitForFile(t, readyPath)
				if err := command.Process.Signal(test.signal); err != nil {
					t.Fatal(err)
				}
				exitCode := waitExitCode(t, command, 8*time.Second, &output)
				if exitCode != test.wantExit {
					t.Fatalf("signaled promoted artifact exit = %d, want %d", exitCode, test.wantExit)
				}
				record, err := os.ReadFile(recordPath)
				if err != nil {
					t.Fatal(err)
				}
				if string(record) != test.wantRecord {
					t.Error("forwarded signal record did not match")
				}
				assertNoSessions(t, home)
			})
		}
	})

	t.Run("PTY terminal resize", func(t *testing.T) {
		home, path := prepareRuntimeHome(t)
		fixtureRoot := realTemporaryDirectory(t)
		toolsDirectory := filepath.Join(fixtureRoot, "tools")
		if err := os.Mkdir(toolsDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		readyPath := filepath.Join(fixtureRoot, "ready")
		recordPath := filepath.Join(fixtureRoot, "resize")
		writeFakeDevin(t, filepath.Join(toolsDirectory, "devin"), successfulFakeDevin(`
trap 'stty size > ./resize' WINCH
touch ./ready
while [ ! -e ./resize ]; do sleep 0.05; done
exit 0
`))
		environment := promotedEnvironment(home, toolsDirectory+string(os.PathListSeparator)+path)

		master, terminal, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer master.Close()
		defer terminal.Close()
		if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "devin", "--profile", "reviews")
		command.Env = environment
		command.Dir = fixtureRoot
		command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Kill() })

		capture := &safeCapture{}
		outputDone := make(chan struct{})
		go capturePTY(master, capture, outputDone)
		waitForFile(t, readyPath)
		if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 40}); err != nil {
			t.Fatal(err)
		}
		wait := make(chan error, 1)
		go func() { wait <- command.Wait() }()
		select {
		case err := <-wait:
			if err != nil {
				t.Fatalf("resized promoted artifact failed: %v", err)
			}
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			t.Fatal("resized promoted artifact timed out")
		}
		if err := terminal.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-outputDone:
		case <-time.After(2 * time.Second):
			t.Fatal("resized promoted artifact output reader did not finish")
		}
		resize, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := strings.TrimSpace(string(resize)), "40 120"; got != want {
			t.Error("fake Devin terminal size did not match")
		}
		assertNoSessions(t, home)
	})

	t.Run("concurrent lease isolation and abandoned cleanup", func(t *testing.T) {
		home, path := prepareRuntimeHome(t)
		abandoned := filepath.Join(home, ".acs", "sessions", "session-abandoned")
		if err := os.MkdirAll(abandoned, 0o700); err != nil {
			t.Fatal(err)
		}
		fixtureRoot := realTemporaryDirectory(t)
		toolsDirectory := filepath.Join(fixtureRoot, "tools")
		if err := os.Mkdir(toolsDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		readyPath := filepath.Join(fixtureRoot, "first-ready")
		releasePath := filepath.Join(fixtureRoot, "release-first")
		writeFakeDevin(t, filepath.Join(toolsDirectory, "devin"), successfulFakeDevin(`
if mkdir ./claim 2>/dev/null; then
  printf '%s\n' "$HOME" > ./first-ready
  while [ ! -e ./release-first ]; do sleep 0.05; done
fi
exit 0
`))
		environment := promotedEnvironment(home, toolsDirectory+string(os.PathListSeparator)+path)
		newCommand := func() (*exec.Cmd, *bytes.Buffer) {
			command := exec.Command(binary, "devin", "--profile", "reviews")
			command.Env = environment
			command.Dir = fixtureRoot
			output := &bytes.Buffer{}
			command.Stdout, command.Stderr = output, output
			return command, output
		}
		first, firstOutput := newCommand()
		if err := first.Start(); err != nil {
			t.Fatal(err)
		}
		waitForFile(t, readyPath)
		firstHomeBytes, err := os.ReadFile(readyPath)
		if err != nil {
			t.Fatal(err)
		}
		firstHome := strings.TrimSpace(string(firstHomeBytes))
		if _, err := os.Stat(firstHome); err != nil {
			t.Fatalf("first isolated Session is unavailable: %v", err)
		}

		second, secondOutput := newCommand()
		if err := second.Start(); err != nil {
			t.Fatal(err)
		}
		if exitCode := waitExitCode(t, second, 8*time.Second, secondOutput); exitCode != 0 {
			t.Fatalf("second concurrent launch exited %d", exitCode)
		}
		if _, err := os.Stat(firstHome); err != nil {
			t.Fatalf("second launch removed the active first Session: %v", err)
		}
		if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
			t.Fatalf("launch did not remove an abandoned Session: %v", err)
		}
		if err := os.WriteFile(releasePath, []byte("release\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if exitCode := waitExitCode(t, first, 8*time.Second, firstOutput); exitCode != 0 {
			t.Fatalf("first concurrent launch exited %d", exitCode)
		}
		assertNoSessions(t, home)
	})
}

func prepareRuntimeHome(t *testing.T) (string, string) {
	t.Helper()
	home := realTemporaryDirectory(t)
	writeSkillBundle(t, home, "review")
	writeVersionOneProfile(t, home, "reviews")
	credential := filepath.Join(home, ".local", "share", "devin", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(credential), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("fixture-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, os.Getenv("PATH")
}

func successfulFakeDevin(interactive string) string {
	return `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  [ -f "$HOME/.local/share/devin/credentials.toml" ] || exit 65
  printf 'Logged in (fixture).\n'
  exit 0
fi
` + interactive
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for fixture state")
}

func waitExitCode(t *testing.T, command *exec.Cmd, timeout time.Duration, output *bytes.Buffer) int {
	t.Helper()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err == nil {
			return 0
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode()
		}
		t.Fatalf("wait for promoted artifact: %v", err)
	case <-time.After(timeout):
		_ = command.Process.Kill()
		t.Fatal("promoted artifact timed out")
	}
	return -1
}

func writeVersionOneProfile(t *testing.T, home, name string) {
	t.Helper()
	directory := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := fmt.Sprintf(`{"version":1,"name":%q,"target":"devin","skillReferences":[{"source":"devin-config","relativePath":"review"}]}`, name)
	if err := os.WriteFile(filepath.Join(directory, name+".json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFakeDevin(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func assertNoSessions(t *testing.T, home string) {
	t.Helper()
	directory := filepath.Join(home, ".acs", "sessions")
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("promoted artifact left Session state")
	}
}

func assertCancelledPTY(t *testing.T, result ptyResult) {
	t.Helper()
	if result.exitCode != 130 {
		t.Fatalf("Profile cancellation exited %d, want 130", result.exitCode)
	}
	if strings.Count(result.output, "\x1b[?1049h") != 1 || strings.Count(result.output, "\x1b[?1049l") != 1 {
		t.Fatal("cancelled builder did not restore the alternate screen exactly once")
	}
	restoredAt := strings.Index(result.output, "\x1b[?1049l")
	if summaryAt := strings.LastIndex(result.output, "Profile creation cancelled."); summaryAt < restoredAt {
		t.Fatal("cancellation summary preceded terminal restoration")
	}
}

func assertProfileAbsent(t *testing.T, home, name string) {
	t.Helper()
	path := filepath.Join(home, ".acs", "profiles", name+".json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cancelled Profile left persistent state: %v", err)
	}
}

func writeSkillBundle(t *testing.T, home, name string) string {
	t.Helper()
	path := filepath.Join(home, ".config", "devin", "skills", name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# "+name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type ptyResult struct {
	exitCode int
	output   string
}

func runPromotedPTY(t *testing.T, binary, home, profileName string, interact func(*testing.T, io.Writer, *safeCapture)) ptyResult {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 30}); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(binary, "devin", "create-profile", "--name", profileName)
	command.Env = promotedEnvironment(home, os.Getenv("PATH"))
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })

	capture := &safeCapture{}
	outputDone := make(chan struct{})
	go capturePTY(master, capture, outputDone)

	interact(t, master, capture)
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("installed Profile Builder timed out")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-outputDone:
	case <-time.After(2 * time.Second):
		t.Fatal("installed Profile Builder output reader did not finish")
	}
	exitCode := 0
	if waitErr != nil {
		var exitError *exec.ExitError
		if !asExitError(waitErr, &exitError) {
			t.Fatalf("wait for installed Profile Builder: %v", waitErr)
		}
		exitCode = exitError.ExitCode()
	}
	return ptyResult{exitCode: exitCode, output: capture.String()}
}

func capturePTY(master io.Reader, capture *safeCapture, done chan<- struct{}) {
	defer close(done)
	buffer := make([]byte, 4096)
	for {
		count, readErr := master.Read(buffer)
		if count > 0 {
			capture.Write(buffer[:count])
		}
		if readErr != nil {
			return
		}
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	exitError, ok := err.(*exec.ExitError)
	if ok {
		*target = exitError
	}
	return ok
}

type safeCapture struct {
	mutex sync.Mutex
	data  strings.Builder
}

func (capture *safeCapture) Write(contents []byte) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	_, _ = capture.data.Write(contents)
}

func (capture *safeCapture) String() string {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return capture.data.String()
}

func waitForOutput(t *testing.T, capture *safeCapture, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(capture.String(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PTY output did not contain %q", marker)
}

func writePTY(t *testing.T, terminal io.Writer, inputs ...string) {
	t.Helper()
	for _, input := range inputs {
		if _, err := io.WriteString(terminal, input); err != nil {
			t.Fatal(err)
		}
		time.Sleep(75 * time.Millisecond)
	}
}

func promotedBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("ACS_PROMOTED_BINARY")
	if path == "" {
		t.Skip("ACS_PROMOTED_BINARY is required for promoted-artifact acceptance")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		t.Fatalf("inspect promoted artifact: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("promoted artifact is not executable")
	}
	return absolute
}

func promotedVersion(t *testing.T) string {
	t.Helper()
	version := os.Getenv("ACS_PROMOTED_VERSION")
	if version == "" {
		t.Fatal("ACS_PROMOTED_VERSION is required for promoted-artifact acceptance")
	}
	return version
}

func promotedSandboxCapability(t *testing.T) string {
	t.Helper()
	capability := os.Getenv("ACS_PROMOTED_SANDBOX_BACKEND")
	if capability == "" {
		t.Fatal("ACS_PROMOTED_SANDBOX_BACKEND is required for promoted-artifact acceptance")
	}
	return capability
}

func promotedEnvironment(home, path string) []string {
	overrides := map[string]string{"HOME": home, "PATH": path, "TERM": "xterm-256color", "NO_COLOR": "1"}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := overrides[key]; overridden {
				continue
			}
		}
		environment = append(environment, entry)
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func realTemporaryDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s permissions = %#o, want %#o", filepath.Base(path), got, want)
	}
}

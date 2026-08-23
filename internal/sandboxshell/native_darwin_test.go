//go:build darwin

package sandboxshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/creack/pty"
)

const nativeShellPTYHarnessEnvironment = "ACS_SANDBOX_SHELL_NATIVE_PTY_HARNESS"

func TestNativeShellBackspaceEditsInteractiveLine(t *testing.T) {
	skipNativeShellTestBinaryUnderRace(t)
	root := t.TempDir()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestNativeShellPTYHarness$")
	command.Env = append(os.Environ(), nativeShellPTYHarnessEnvironment+"=1", "ACS_SANDBOX_SHELL_NATIVE_PTY_ROOT="+root)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}

	capture := &nativeShellPTYCapture{}
	readerDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(capture, master)
		close(readerDone)
	}()
	waitForNativeShellPTYOutput(t, capture, "% ")
	if _, err := master.Write([]byte("PS1='ACS> '\n")); err != nil {
		t.Fatal(err)
	}
	waitForNativeShellPTYOutput(t, capture, "ACS> ")
	if _, err := master.Write([]byte("abcdef\x7f\x7f\x7fXYZ\n")); err != nil {
		t.Fatal(err)
	}
	waitForNativeShellPTYOutput(t, capture, "command not found: abcXYZ")
	if _, err := master.Write([]byte("exit 0\n")); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("native sandbox shell PTY harness: %v; output: %q", err, capture.String())
	}
	_ = master.Close()
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("native sandbox shell PTY reader did not finish")
	}
}

func TestNativeShellPTYHarness(t *testing.T) {
	if os.Getenv(nativeShellPTYHarnessEnvironment) != "1" {
		return
	}
	t.Setenv("TERM", "xterm-256color")
	root := os.Getenv("ACS_SANDBOX_SHELL_NATIVE_PTY_ROOT")
	if root == "" || !filepath.IsAbs(root) {
		t.Fatal("native sandbox shell PTY root is unavailable")
	}
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	exitCode, err := New().Launch(
		context.Background(),
		filepath.Join(root, "sessions"),
		workingDirectory,
		resolvedShellProfile(t),
		launch.Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr},
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("native sandbox shell PTY launch = (%d, %v)", exitCode, err)
	}
}

type nativeShellPTYCapture struct {
	mu sync.Mutex
	bytes.Buffer
}

func (capture *nativeShellPTYCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.Buffer.Write(contents)
}

func (capture *nativeShellPTYCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.Buffer.String()
}

func waitForNativeShellPTYOutput(t *testing.T, capture *nativeShellPTYCapture, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(capture.String(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("native sandbox shell PTY output did not contain %q: %q", marker, capture.String())
}

func TestNativeShellProvidesTerminalCapabilitiesForLineEditing(t *testing.T) {
	skipNativeShellTestBinaryUnderRace(t)
	t.Setenv("TERM", "xterm-256color")
	root := t.TempDir()
	sessionsDirectory := filepath.Join(root, "sessions")
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	commands := `set -eu
zmodload zsh/terminfo
echoti cub1 >/dev/null
print -r -- terminal-capability-ok
exit 0
`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := New().Launch(
		context.Background(),
		sessionsDirectory,
		workingDirectory,
		resolvedShellProfile(t),
		launch.Terminal{Input: strings.NewReader(commands), Output: &stdout, ErrorOutput: &stderr},
	)
	if err != nil {
		t.Fatalf("launch native sandbox shell: %v; stdout: %s; stderr: %s", err, stdout.String(), stderr.String())
	}
	if exitCode != 0 || !strings.Contains(stdout.String(), "terminal-capability-ok") {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestNativeShellContainsFilesystemAndCleansDescendantAndSession(t *testing.T) {
	skipNativeShellTestBinaryUnderRace(t)
	root := t.TempDir()
	sessionsDirectory := filepath.Join(root, "sessions")
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideSecret := filepath.Join(outside, "host-secret")
	if err := os.WriteFile(outsideSecret, []byte("must stay hidden\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	commands := fmt.Sprintf(`set -eu
test "$(cat "$HOME/.agents/skills/review/SKILL.md")" = selected
printf session-home > "$HOME/home-proof"
printf workspace > ./workspace-proof
if cat %s >/dev/null 2>&1; then
  exit 71
fi
sleep 30 &
print -r -- $! > ./descendant.pid
print -r -- sandbox-ok
exit 0
`, strconv.Quote(outsideSecret))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := New().Launch(
		context.Background(),
		sessionsDirectory,
		workingDirectory,
		resolvedShellProfile(t),
		launch.Terminal{Input: strings.NewReader(commands), Output: &stdout, ErrorOutput: &stderr},
	)
	if err != nil {
		t.Fatalf("launch native sandbox shell: %v; stderr: %s", err, stderr.String())
	}
	if exitCode != 0 || !strings.Contains(stdout.String(), "sandbox-ok") {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "startup-file-loaded") {
		t.Fatalf("/bin/zsh -f loaded a Session startup file: %q", stdout.String())
	}
	if contents, err := os.ReadFile(filepath.Join(workingDirectory, "workspace-proof")); err != nil || string(contents) != "workspace" {
		t.Fatalf("workspace write = %q, %v", contents, err)
	}
	descendantContents, err := os.ReadFile(filepath.Join(workingDirectory, "descendant.pid"))
	if err != nil {
		t.Fatal(err)
	}
	descendantPID, err := strconv.Atoi(strings.TrimSpace(string(descendantContents)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(descendantPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(descendantPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("sandbox descendant %d survived shell completion: %v", descendantPID, err)
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("completed shell left Session %q behind", entry.Name())
		}
	}
}

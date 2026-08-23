//go:build darwin

package sandboxshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

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

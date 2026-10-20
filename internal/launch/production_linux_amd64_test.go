//go:build linux && amd64

package launch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
)

func TestLinuxProductionCommandRunsInsideTheSandbox(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, check := range report.Checks {
			if check.Status != "pass" {
				missing = append(missing, check.ID+":"+check.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	base := t.TempDir()
	sessions := filepath.Join(base, "sessions")
	workspace := filepath.Join(base, "work")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	lease, err := CreateProtectedSession(sessions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Remove() })
	home := filepath.Join(lease.RootDir, "home")
	temporary := filepath.Join(lease.RootDir, "tmp")
	if err := os.Mkdir(home, 0o700); err != nil || os.Mkdir(temporary, 0o700) != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x41}, RecoveryProofChallengeSize)
	if err := PrepareSessionCleanupProof(lease.RootDir, challenge); err != nil {
		t.Fatal(err)
	}
	sandbox := newNativeProcessSandbox(CurrentPlatform, nativeSandboxBackends())
	process, err := sandbox.Prepare(context.Background(), ProcessRequest{
		Workspace: workspace, WorkspaceAccess: WorkspaceAccessReadOnly,
		SessionsDirectory: sessions, SessionDirectory: lease.RootDir,
		SessionHome: home, TemporaryDirectory: temporary,
		Executable: "/usr/bin/true", Arguments: nil,
		RecoveryProofChallenge: challenge,
		Terminal:               Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.(ProcessCleanup).CleanupDone():
	default:
		t.Fatal("settled command did not publish cleanup")
	}
}

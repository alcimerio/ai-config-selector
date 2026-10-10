package launch

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// This needs a PTY, not namespaces, Landlock or delegated cgroups. It exercises
// real terminal queues and foreground ownership in a disposable new session.
func TestLinuxNativeCleanupRestoresTTYAndFlushesPendingInput(t *testing.T) {
	linuxCleanupPrerequisites(t)
	master, slave, err := pty.Open()
	if err != nil {
		linuxNativeUnavailable(t, "open a private PTY: "+err.Error())
	}
	defer master.Close()
	defer slave.Close()
	ready, report, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer report.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxCleanupTTYHelper$")
	cmd.Env = append(os.Environ(), "ACS_TEST_CLEANUP_TTY=1", "ACS_TEST_ROOT="+t.TempDir())
	cmd.Stdin, cmd.Stdout = slave, slave
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	cmd.ExtraFiles = []*os.File{report}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		linuxNativeUnavailable(t, "create a session with a controlling PTY: "+err.Error())
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = report.Close()
	_ = ready.SetReadDeadline(time.Now().Add(5 * time.Second))
	var receipt [1]byte
	if _, err := io.ReadFull(ready, receipt[:]); err != nil || receipt[0] != 'R' {
		t.Fatalf("PTY helper readiness: %v", err)
	}
	if _, err := master.Write([]byte("pending-shell-input\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("PTY cleanup failed: %v: %s", err, diagnostics.String())
	}
}

func TestLinuxCleanupTTYHelper(t *testing.T) {
	if os.Getenv("ACS_TEST_CLEANUP_TTY") != "1" {
		return
	}
	lease, err := CreateProtectedSession(filepath.Join(os.Getenv("ACS_TEST_ROOT"), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Remove()
	challenge := bytes.Repeat([]byte{0xc5}, RecoveryProofChallengeSize)
	if err := PrepareSessionCleanupProof(lease.RootDir, challenge); err != nil {
		t.Fatal(err)
	}
	c, err := linuxPrepareCleanup(lease, challenge, os.Stdin)
	if err != nil || c.terminal == nil {
		t.Fatalf("capture controlling terminal: %v", err)
	}
	original := c.terminal.attrs
	changed := original
	changed.Lflag &^= unix.ICANON | unix.ECHO
	changed.Cc[unix.VMIN] = 1
	if err := unix.IoctlSetTermios(0, unix.TCSETS, &changed); err != nil {
		t.Fatal(err)
	}
	report := os.NewFile(3, "pty-ready")
	if _, err := report.Write([]byte{'R'}); err != nil {
		t.Fatal(err)
	}
	_ = report.Close()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(time.Millisecond) {
		queued, err := unix.IoctlGetInt(0, unix.TIOCINQ)
		if err != nil {
			t.Fatal(err)
		}
		if queued == len("pending-shell-input\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("input did not enter terminal queue")
		}
	}
	// Relinquish foreground ownership to a short-lived group so restoration
	// must operate from the background, without changing SIGTTOU globally.
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, child.Process.Pid); err != nil {
		t.Fatal(err)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	if err := c.finish(true); err != nil {
		t.Fatal(err)
	}
	queued, err := unix.IoctlGetInt(0, unix.TIOCINQ)
	if err != nil || queued != 0 {
		t.Fatalf("pending input after restore: %d, %v", queued, err)
	}
	attrs, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil || *attrs != original {
		t.Fatal("terminal attributes were not restored")
	}
	group, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil || group != unix.Getpgrp() {
		t.Fatal("foreground group was not restored")
	}
}

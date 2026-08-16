//go:build linux

package devin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

const launchPTYSignalHelperEnvironment = "ACS_LAUNCH_PTY_SIGNAL_HELPER"

func TestLaunchRoutesDirectSignalsFromPTYAttachedACS(t *testing.T) {
	for _, test := range []struct {
		name       string
		signal     syscall.Signal
		trap       string
		wantExit   int
		wantRecord string
		terminal   bool
	}{
		{name: "termination", signal: syscall.SIGTERM, trap: "TERM", wantExit: 42, wantRecord: "SIGTERM\n"},
		{name: "resize", signal: syscall.SIGWINCH, trap: "WINCH", wantExit: 0, wantRecord: "SIGWINCH\n"},
		{name: "terminal resize", trap: "WINCH", wantExit: 0, wantRecord: "SIGWINCH\n", terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "ready")
			record := filepath.Join(t.TempDir(), "record")
			binary := writeFakeDevin(t, successfulDevinScript("trap 'printf \""+test.wantRecord[:len(test.wantRecord)-1]+"\\n\" > \"$ACS_LAUNCH_PTY_SIGNAL_RECORD\"; exit "+strconv.Itoa(test.wantExit)+"' "+test.trap+"\ntouch \"$ACS_LAUNCH_PTY_SIGNAL_READY\"\nwhile :; do sleep 1; done\n"))

			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestLaunchPTYSignalHelper$")
			command.Env = append(os.Environ(),
				launchPTYSignalHelperEnvironment+"=1",
				"ACS_LAUNCH_PTY_SIGNAL_BINARY="+binary,
				"ACS_LAUNCH_PTY_SIGNAL_READY="+ready,
				"ACS_LAUNCH_PTY_SIGNAL_RECORD="+record,
			)
			command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill() })
			if err := terminal.Close(); err != nil {
				t.Fatal(err)
			}
			waitForFile(t, ready)
			if test.terminal {
				if err := pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
					t.Fatal(err)
				}
			} else if err := command.Process.Signal(test.signal); err != nil {
				t.Fatal(err)
			}
			if exitCode := waitPTYSignalHelper(t, command); exitCode != test.wantExit {
				t.Fatalf("direct %s launch exit = %d, want %d", test.signal, exitCode, test.wantExit)
			}
			contents, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(contents); got != test.wantRecord {
				t.Fatalf("direct %s target record = %q, want %q", test.signal, got, test.wantRecord)
			}
		})
	}
}

func TestLaunchPTYSignalHelper(t *testing.T) {
	if os.Getenv(launchPTYSignalHelperEnvironment) != "1" {
		return
	}
	fixture := newLaunchTestFixture(t)
	application := fixture.application(
		t,
		os.Getenv("ACS_LAUNCH_PTY_SIGNAL_BINARY"),
		t.TempDir(),
		os.Stdin,
		os.Stdout,
		os.Stderr,
	)
	os.Exit(application.Run(context.Background(), []string{"devin", "--profile", "reviews"}))
}

func waitPTYSignalHelper(t *testing.T, command *exec.Cmd) int {
	t.Helper()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err == nil {
			return 0
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		<-wait
		t.Fatal("PTY-attached ACS did not route its direct signal")
	}
	return 0
}

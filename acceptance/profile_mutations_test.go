//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
)

func mutationCandidateHome(t *testing.T) (string, string, []byte) {
	t.Helper()
	home := realTemporaryDirectory(t)
	path := filepath.Join(home, ".acs", "profiles", "old.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"lost"}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return home, path, raw
}

func runMutationCandidatePTY(t *testing.T, binary, home string, args []string, interact func(*os.File, *safeCapture, *os.Process)) ptyResult {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 35}); err != nil {
		t.Fatal(err)
	}
	before, err := term.GetState(terminal.Fd())
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Env = promotedEnvironment(home, "/nonexistent")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.Dir = home
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	capture := &safeCapture{}
	done := make(chan struct{})
	go capturePTY(master, capture, done)
	interact(master, capture, command.Process)
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("mutation timed out: %q", capture.String())
	}
	after, err := term.GetState(terminal.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("mutation failed to restore terminal attributes")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mutation capture did not finish")
	}
	code := 0
	if waitErr != nil {
		var exit *exec.ExitError
		if !errors.As(waitErr, &exit) {
			t.Fatal(waitErr)
		}
		code = exit.ExitCode()
	}
	output := capture.String()
	if strings.Count(output, "\x1b[?1049h") != 1 || strings.Count(output, "\x1b[?1049l") != 1 {
		t.Fatalf("mutation alternate screen restoration: %q", output)
	}
	return ptyResult{exitCode: code, output: output}
}

func TestPromotedProfileMutationSeedPreviewAndCommit(t *testing.T) {
	binary := promotedBinary(t)
	for _, operation := range []string{"edit", "clone", "rename"} {
		t.Run(operation, func(t *testing.T) {
			home, path, raw := mutationCandidateHome(t)
			args := []string{"profile", operation, "old"}
			destination := "old"
			if operation != "edit" {
				args = append(args, "--name", "new")
				destination = "new"
			}
			result := runMutationCandidatePTY(t, binary, home, args, func(master *os.File, capture *safeCapture, _ *os.Process) {
				if operation != "rename" {
					waitForOutput(t, capture, strings.ToUpper(operation[:1])+operation[1:]+` Profile "`+destination+`"`)
					writePTY(t, master, "\r")
					waitForOutput(t, capture, "[x] lost [devin-config:lost] missing")
					writePTY(t, master, "\x1b[D", "\x1b[B", "\r")
				}
				waitForOutput(t, capture, "Stored v1 -> v2")
				writePTY(t, master, "\x1b[F")
				waitForOutput(t, capture, "acknowledge unresolved")
				// No generic confirmation may bypass availability acknowledgement.
				writePTY(t, master, "\r")
				existing, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(existing, raw) {
					t.Fatal("unacknowledged preview changed original")
				}
				writePTY(t, master, "a", "\r")
			})
			if result.exitCode != 0 || !strings.Contains(result.output, "Profile committed:") {
				t.Fatalf("mutation result: %d %q", result.exitCode, result.output)
			}
			stored, err := os.ReadFile(filepath.Join(home, ".acs", "profiles", destination+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(stored, []byte(`"version": 2`)) || !bytes.Contains(stored, []byte(`"name": "`+destination+`"`)) || !bytes.Contains(stored, []byte(`"relativePath": "lost"`)) {
				t.Fatalf("lost stored intention: %s", stored)
			}
			if operation == "clone" {
				existing, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(existing, raw) {
					t.Fatal("clone changed source")
				}
			}
			if operation == "rename" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("rename retained source")
				}
			}
			assertNoSessions(t, home)
		})
	}
}

func TestPromotedProfileMutationCancelSignalResizeAndDeleteConfirmation(t *testing.T) {
	binary := promotedBinary(t)
	for _, scenario := range []string{"cancel", "signal", "resize", "mismatch", "eof", "delete"} {
		t.Run(scenario, func(t *testing.T) {
			home, path, raw := mutationCandidateHome(t)
			before := snapshotInspectionHome(t, home)
			command := "edit"
			if scenario == "mismatch" || scenario == "delete" || scenario == "eof" {
				command = "delete"
			}
			result := runMutationCandidatePTY(t, binary, home, []string{"profile", command, "old"}, func(master *os.File, capture *safeCapture, process *os.Process) {
				if command == "delete" {
					waitForOutput(t, capture, "Type exact name old")
					if scenario == "delete" {
						writePTY(t, master, "old", "\r")
						return
					}
					if scenario == "eof" {
						writePTY(t, master, "\x04")
						return
					}
					writePTY(t, master, "OLD", "\r")
					existing, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(existing, raw) {
						t.Fatal("mismatch deleted Profile")
					}
					writePTY(t, master, "\x03")
					return
				}
				waitForOutput(t, capture, `Edit Profile "old"`)
				if scenario == "signal" {
					if err := process.Signal(syscall.SIGTERM); err != nil {
						t.Fatal(err)
					}
					return
				}
				if scenario == "resize" {
					writePTY(t, master, "\r")
					waitForOutput(t, capture, "[x] lost")
					if err := pty.Setsize(master, &pty.Winsize{Cols: 40, Rows: 10}); err != nil {
						t.Fatal(err)
					}
					waitForOutput(t, capture, "Terminal too small")
					if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 35}); err != nil {
						t.Fatal(err)
					}
				}
				writePTY(t, master, "\x03")
			})
			if scenario == "delete" {
				if result.exitCode != 0 {
					t.Fatalf("delete: %d %q", result.exitCode, result.output)
				}
				assertProfileAbsent(t, home, "old")
				return
			}
			if scenario != "signal" && result.exitCode != 130 {
				t.Fatalf("cancel: %d %q", result.exitCode, result.output)
			}
			if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
				t.Fatal("cancel/signal/mismatch changed bytes/modes/tree")
			}
		})
	}
}

func TestPromotedProfileMutationInformationalAndNoninteractiveTripwires(t *testing.T) {
	binary := promotedBinary(t)
	home, _, _ := mutationCandidateHome(t)
	tripwire := filepath.Join(home, ".acs", "profiles", ".profile-transaction-decision")
	if err := os.WriteFile(tripwire, []byte("preserve malformed pending recovery"), 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotInspectionHome(t, home)
	for _, args := range [][]string{{"profile", "edit", "--help"}, {"profile", "clone", "--help"}, {"profile", "rename", "--help"}, {"profile", "delete", "--help"}, {"profile", "edit", "old"}, {"profile", "clone", "old", "--name", "new"}, {"profile", "rename", "old", "--name", "new"}, {"profile", "delete", "old"}, {"profile", "delete", "old", "--confirm", "OLD"}, {"profile", "edit", "../outside"}} {
		cmd := exec.Command(binary, args...)
		cmd.Env = []string{"HOME=" + home, "PATH=/nonexistent", "TERM=xterm", "LANG=C", "LC_ALL=C", "LC_CTYPE=C"}
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		err := cmd.Run()
		help := args[len(args)-1] == "--help"
		if help && err != nil || !help && err == nil {
			t.Fatalf("unexpected result %q: %v %s", args, err, &output)
		}
		if strings.Contains(output.String(), "recover preceding") || strings.Contains(output.String(), "resolve user home") {
			t.Fatalf("preflight reached recovery/runtime: %s", &output)
		}
	}
	if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
		t.Fatal("informational/noninteractive paths changed tree")
	}
}

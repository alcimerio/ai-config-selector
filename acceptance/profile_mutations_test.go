//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
)

func TestPromotedProfileHistoryDiffDeleteAndRestoreArePublicAndPassive(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	input := filepath.Join(home, "profile.json")
	document := []byte(`{"version":3,"name":"history-demo","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"private-history-auth-canary"},"devin":{"version":1}}}`)
	if err := os.WriteFile(input, document, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		command := exec.Command(binary, args...)
		command.Env = promotedEnvironment(home, "/nonexistent")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("acs %v: %v %s", args, err, output)
		}
		return output
	}
	run("profile", "create", "--file", input)
	var history struct {
		LineageID string `json:"lineageId"`
		Events    []struct {
			EventID string `json:"eventId"`
		} `json:"events"`
	}
	if err := json.Unmarshal(run("profile", "history", "history-demo", "--json"), &history); err != nil || len(history.Events) != 1 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	before := snapshotInspectionHome(t, home)
	diff := run("profile", "diff", "history-demo", "--revision", history.Events[0].EventID, "--json")
	if bytes.Contains(diff, []byte("private-history-auth-canary")) {
		t.Fatalf("diff leaked auth reference: %s", diff)
	}
	preview := run("profile", "restore", "history-demo", "--revision", history.Events[0].EventID, "--dry-run", "--json")
	if bytes.Contains(preview, []byte("private-history-auth-canary")) {
		t.Fatalf("restore preview leaked auth reference: %s", preview)
	}
	if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
		t.Fatal("passive history command changed home")
	}
	run("profile", "delete", "history-demo", "--confirm", "history-demo")
	var deleted struct {
		Events []struct {
			EventID string `json:"eventId"`
			Profile struct {
				State string `json:"state"`
			} `json:"profile"`
		} `json:"events"`
	}
	if err := json.Unmarshal(run("profile", "history", "--lineage", history.LineageID, "--json"), &deleted); err != nil || len(deleted.Events) < 2 || deleted.Events[0].Profile.State != "deleted" {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	bindings := filepath.Join(home, "restore-bindings.json")
	if err := os.WriteFile(bindings, []byte(`{"bindingVersion":1,"sources":{},"authentications":{"authentication-1":"restored-history-auth"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	preview = run("profile", "restore", "--lineage", history.LineageID, "--revision", deleted.Events[0].EventID, "--bindings", bindings, "--dry-run", "--json")
	var restore struct {
		Digest      string `json:"digest"`
		Destination string `json:"destination"`
	}
	if err := json.Unmarshal(preview, &restore); err != nil || restore.Digest == "" || restore.Destination != "history-demo" {
		t.Fatalf("restore=%+v err=%v", restore, err)
	}
	run("profile", "restore", "--lineage", history.LineageID, "--revision", deleted.Events[0].EventID, "--bindings", bindings, "--expect", restore.Digest, "--confirm", "history-demo", "--json")
	if _, err := os.Stat(filepath.Join(home, ".acs", "profiles", "history-demo.json")); err != nil {
		t.Fatal(err)
	}
	assertNoSessions(t, home)
}

const newerMutationProfile = `{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[{"source":"shared-agents","relativePath":"newer"}]}}}`

// A separate process uses the production transaction boundary while the editor
// retains its previously captured revision. It never touches the user's home.
func TestProfileMutationWriterHelper(t *testing.T) {
	home := os.Getenv("ACS_MUTATION_WRITER_HOME")
	if home == "" {
		t.Skip("independent writer helper")
	}
	repository := profilerepo.New(filepath.Join(home, ".acs"))
	snapshot, err := repository.Read(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := repository.Apply(context.Background(), profilerepo.ReplaceRequest{Name: "old", Expected: snapshot.Revision, Bytes: []byte(newerMutationProfile)})
	if err != nil || outcome.State != profilerepo.Committed {
		t.Fatalf("writer: %v %v", outcome, err)
	}
}

func TestPromotedProfileMutationReloadThenSignalReportsCurrentCancellation(t *testing.T) {
	binary := promotedBinary(t)
	for _, operation := range []string{"edit", "clone"} {
		t.Run(operation, func(t *testing.T) {
			home, path, _ := mutationCandidateHome(t)
			args := []string{"profile", operation, "old"}
			if operation == "clone" {
				args = append(args, "--name", "new")
			}
			result := runMutationCandidatePTY(t, binary, home, args, func(master *os.File, capture *safeCapture, process *os.Process) {
				waitForOutput(t, capture, "Profile \"")
				writePTY(t, master, "\x1b[B", "\x1b[B", "\x1b[B", "\r")
				waitForOutput(t, capture, "Stored v1 -> v2")
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				writer := exec.Command(executable, "-test.run=^TestProfileMutationWriterHelper$", "-test.v")
				writer.Env = append(promotedEnvironment(home, "/nonexistent"), "ACS_MUTATION_WRITER_HOME="+home)
				if output, err := writer.CombinedOutput(); err != nil {
					t.Fatalf("independent writer: %v %s", err, output)
				}
				writePTY(t, master, "\x1b[F", "a", "y")
				waitForOutput(t, capture, "Storage changed. Your draft")
				writePTY(t, master, "r", "\r", "l")
				waitForOutput(t, capture, "Reload stored Profile?")
				writePTY(t, master, "y", "\x1b[A", "\x1b[A", "\x1b[A", "\r")
				waitForOutput(t, capture, "[x] newer")
				if err := process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			})
			if result.exitCode != 130 || strings.Contains(result.output, "storage changed; mutation not committed") {
				t.Fatalf("retired conflict overrode current cancellation: %d %q", result.exitCode, result.output)
			}
			stored, err := os.ReadFile(path)
			if err != nil || string(stored) != newerMutationProfile {
				t.Fatal("newer Profile changed")
			}
			assertProfileAbsent(t, home, "new")
			assertNoSessions(t, home)
		})
	}
}

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
	before, err := term.GetState(master.Fd())
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
	after, err := term.GetState(master.Fd())
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
					writePTY(t, master, "\x1b[D", "\x1b[B", "\x1b[B", "\x1b[B", "\r")
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

func TestPromotedProfileExplicitMigrationPreservesWorkspaceWriteAndAdoptsCommonPaths(t *testing.T) {
	binary := promotedBinary(t)
	home, path, _ := mutationCandidateHome(t)
	result := runMutationCandidatePTY(t, binary, home, []string{"profile", "migrate", "old"}, func(master *os.File, capture *safeCapture, _ *os.Process) {
		waitForOutput(t, capture, `Migrate Profile "old"`)
		writePTY(t, master, "\x1b[B", "\x1b[B", "\x1b[B", "\r")
		waitForOutput(t, capture, "Stored v1 -> v3")
		for _, marker := range []string{"workspace write is retained", ".acs/common/v1/skills", "Devin projection paths"} {
			waitForOutput(t, capture, marker)
		}
		writePTY(t, master, "\x1b[F", "a", "\r")
	})
	if result.exitCode != 0 || !strings.Contains(result.output, "Migrate Profile committed: old") {
		t.Fatalf("migration result: %d %q", result.exitCode, result.output)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range [][]byte{[]byte(`"version": 3`), []byte(`"common"`), []byte(`"workspace"`), []byte(`"access": "read-write"`), []byte(`"overlays"`), []byte(`"devin"`)} {
		if !bytes.Contains(stored, fragment) {
			t.Fatalf("migrated Profile omits %s: %s", fragment, stored)
		}
	}
}

func TestPromotedProfileExplicitMigrationPreviewsSelectedWorkspaceReduction(t *testing.T) {
	binary := promotedBinary(t)
	home, path, _ := mutationCandidateHome(t)
	result := runMutationCandidatePTY(t, binary, home, []string{"profile", "migrate", "old"}, func(master *os.File, capture *safeCapture, _ *os.Process) {
		waitForOutput(t, capture, `Migrate Profile "old"`)
		writePTY(t, master, "\x1b[B", "\r")
		waitForOutput(t, capture, "Workspace access")
		writePTY(t, master, " ", "\x1b[D", "\x1b[B", "\x1b[B", "\r")
		waitForOutput(t, capture, "workspace authority is reduced")
		writePTY(t, master, "\x1b[F", "a", "\r")
	})
	if result.exitCode != 0 {
		t.Fatalf("migration reduction result: %d %q", result.exitCode, result.output)
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(stored, []byte(`"access": "read-only"`)) {
		t.Fatalf("migration did not persist the separately selected reduction: %s %v", stored, err)
	}
}

func TestPromotedProfileMutationCancelSignalResizeAndDeleteConfirmation(t *testing.T) {
	binary := promotedBinary(t)
	for _, scenario := range []string{"cancel", "signal", "resize", "mismatch", "ctrl-d", "delete"} {
		t.Run(scenario, func(t *testing.T) {
			home, path, raw := mutationCandidateHome(t)
			before := snapshotInspectionHome(t, home)
			command := "edit"
			if scenario == "mismatch" || scenario == "delete" || scenario == "ctrl-d" {
				command = "delete"
			}
			result := runMutationCandidatePTY(t, binary, home, []string{"profile", command, "old"}, func(master *os.File, capture *safeCapture, process *os.Process) {
				if command == "delete" {
					waitForOutput(t, capture, "Type exact name old")
					if scenario == "delete" {
						writePTY(t, master, "old", "\r")
						return
					}
					if scenario == "ctrl-d" {
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

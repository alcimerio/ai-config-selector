package scripts_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBoundedTestCommandPreservesResultsAndCleansTimedOutGroup(t *testing.T) {
	if os.Getenv("ACS_BOUNDED_TEST_RETAIN_OUTPUT") == "1" {
		child := exec.Command("sleep", "60")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(97)
		}
		if err := os.WriteFile(os.Getenv("ACS_BOUNDED_TEST_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(98)
		}
		_, _ = os.Stdout.WriteString("retained-output-marker")
		os.Exit(0)
	}
	script := "./run-bounded-test-command.sh"
	t.Run("success", func(t *testing.T) {
		output, err := exec.Command(script, "5", "bash", "-c", "printf success-marker").CombinedOutput()
		if err != nil || string(output) != "success-marker" {
			t.Fatalf("success = (%q, %v)", output, err)
		}
	})
	t.Run("failure", func(t *testing.T) {
		output, err := exec.Command(script, "5", "bash", "-c", "printf failure-marker; exit 23").CombinedOutput()
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 23 || string(output) != "failure-marker" {
			t.Fatalf("failure = (%q, %v)", output, err)
		}
	})
	t.Run("periodic progress", func(t *testing.T) {
		output, err := exec.Command("env", "ACS_BOUNDED_TEST_PROGRESS_SECONDS=1", script, "5", "bash", "-c", "echo progress-marker; sleep 2").CombinedOutput()
		if err != nil || !strings.Contains(string(output), "bounded test command progress: 1s elapsed") || !strings.Contains(string(output), "progress-marker") {
			t.Fatalf("periodic progress = (%q, %v)", output, err)
		}
	})
	for _, test := range []struct {
		name string
		shim string
	}{
		{name: "child identity lookup fails", shim: "exit 1\n"},
		{name: "wrapper identity lookup fails", shim: "count=0; [ ! -f \"$ACS_PS_CALLS\" ] || read -r count <\"$ACS_PS_CALLS\"; count=$((count + 1)); printf '%s\\n' \"$count\" >\"$ACS_PS_CALLS\"; [ \"$count\" -ne 2 ] || exit 1; exec /usr/bin/ps \"$@\"\n"},
		{name: "child identity mismatches", shim: "count=0; [ ! -f \"$ACS_PS_CALLS\" ] || read -r count <\"$ACS_PS_CALLS\"; count=$((count + 1)); printf '%s\\n' \"$count\" >\"$ACS_PS_CALLS\"; if [ \"$count\" -eq 1 ]; then echo 1; exit 0; fi; exec /usr/bin/ps \"$@\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			shimDir := filepath.Join(root, "bin")
			if err := os.Mkdir(shimDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(shimDir, "ps"), []byte("#!/bin/sh\n"+test.shim), 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "payload-started")
			calls := filepath.Join(root, "ps-calls")
			command := exec.Command(script, "1", "bash", "-c", "printf started >\"$1\"; sleep 60 & wait", "gated-payload", marker)
			command.Env = append(os.Environ(), "PATH="+shimDir+":"+os.Getenv("PATH"), "ACS_PS_CALLS="+calls)
			started := time.Now()
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
				t.Fatalf("identity refusal = (%q, %v)", output, err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("identity refusal exceeded bound: %v", elapsed)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("identity refusal released payload: %v", err)
			}
		})
	}
	t.Run("retained output descendant", func(t *testing.T) {
		childPath := filepath.Join(t.TempDir(), "child")
		command := exec.Command(script, "5", "env", "ACS_BOUNDED_TEST_RETAIN_OUTPUT=1", "ACS_BOUNDED_TEST_CHILD_PID="+childPath, os.Args[0], "-test.run=^TestBoundedTestCommandPreservesResultsAndCleansTimedOutGroup$")
		started := time.Now()
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "retained-output-marker") {
			t.Fatalf("retained-output result = (%q, %v)", output, err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("retained-output command exceeded bound: %v", elapsed)
		}
		assertProcessGone(t, childPath)
	})
	t.Run("timeout", func(t *testing.T) {
		root := t.TempDir()
		parentPath := filepath.Join(root, "parent")
		childPath := filepath.Join(root, "child")
		command := "printf '%s' \"$$\" > \"$1\"; sleep 60 & printf '%s' \"$!\" > \"$2\"; wait"
		started := time.Now()
		output, err := exec.Command(script, "1", "bash", "-c", command, "bounded-child", parentPath, childPath).CombinedOutput()
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 124 {
			t.Fatalf("timeout = (%q, %v)", output, err)
		}
		if elapsed := time.Since(started); elapsed > 10*time.Second {
			t.Fatalf("timeout command exceeded cleanup bound: %v", elapsed)
		}
		if !strings.Contains(string(output), "bounded test command exceeded 1s") {
			t.Fatalf("timeout diagnostic = %q", output)
		}
		for _, path := range []string{parentPath, childPath} {
			assertProcessGone(t, path)
		}
	})
	t.Run("unrelated process survives timeout", func(t *testing.T) {
		unrelated := exec.Command("sleep", "60")
		if err := unrelated.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = unrelated.Process.Kill()
			_, _ = unrelated.Process.Wait()
		}()
		output, err := exec.Command(script, "1", "bash", "-c", "while :; do sleep 1; done").CombinedOutput()
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 124 {
			t.Fatalf("timeout = (%q, %v)", output, err)
		}
		if !processExists(unrelated.Process.Pid) {
			t.Fatal("bounded timeout signaled an unrelated process")
		}
	})
}

func assertProcessGone(t *testing.T, path string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processExists(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processExists(pid) {
		t.Fatalf("bounded process-group member %d remains", pid)
	}
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

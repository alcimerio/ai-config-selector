//go:build darwin || linux

package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const ptyHelperEnvironment = "ACS_PROFILE_BUILDER_PTY_HELPER"

func TestProfileBuilderPTYRestoresTerminal(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		initial  *pty.Winsize
		want     []string
		after    []string
	}{
		{name: "normal completion", scenario: "complete", want: []string{"OUTCOME create", `Created Profile`}, after: []string{"OUTCOME create", "Created Profile"}},
		{name: "Ctrl+C confirmation", scenario: "ctrl-c", want: []string{"Confirm: Discard changes?", "OUTCOME cancelled"}, after: []string{"OUTCOME cancelled"}},
		{name: "resize propagation", scenario: "resize", initial: &pty.Winsize{Cols: 50, Rows: 10}, want: []string{"Terminal too small", `Create Profile "pty"`, "OUTCOME cancelled"}, after: []string{"OUTCOME cancelled"}},
		{name: "recovered panic", scenario: "panic", want: []string{"Caught panic:", "RUNTIME ERROR", "program experienced a panic"}, after: []string{"Caught panic:", "RUNTIME ERROR"}},
		{name: "runtime error", scenario: "runtime-error", want: []string{"RUNTIME ERROR"}, after: []string{"RUNTIME ERROR"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, before, after := runPTYScenario(t, test.scenario, test.initial)
			for _, want := range test.want {
				if !strings.Contains(output, want) {
					t.Errorf("PTY output omits %q:\n%q", want, output)
				}
			}
			if strings.Count(output, "\x1b[?1049h") != 1 || strings.Count(output, "\x1b[?1049l") != 1 {
				t.Errorf("alternate screen was not entered and exited exactly once: %q", output)
			}
			restoredAt := strings.Index(output, "\x1b[?1049l")
			for _, marker := range test.after {
				if strings.Index(output, marker) < restoredAt {
					t.Errorf("%q was printed before alternate-screen restoration: %q", marker, output)
				}
			}
			const canonicalFlags = unix.ICANON | unix.ECHO
			if before.Lflag&canonicalFlags != after.Lflag&canonicalFlags {
				t.Errorf("terminal canonical/echo flags = %#x after run, want %#x", after.Lflag&canonicalFlags, before.Lflag&canonicalFlags)
			}
		})
	}
}

func runPTYScenario(t *testing.T, scenario string, initial *pty.Winsize) (string, *unix.Termios, *unix.Termios) {
	t.Helper()
	if initial == nil {
		initial = &pty.Winsize{Cols: 80, Rows: 24}
	}
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, initial); err != nil {
		t.Fatal(err)
	}
	before, err := readTerminalAttributes(int(master.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(os.Args[0], "-test.run=^TestProfileBuilderPTYHelper$")
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), ptyHelperEnvironment+"="+scenario, "TERM=xterm-256color", "NO_COLOR=1")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	capture := &ptyCapture{}
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
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
	}()

	initialMarker := `Create Profile "pty"`
	if scenario == "resize" {
		initialMarker = "Terminal too small"
	}
	waitForPTYOutput(t, capture, initialMarker)
	switch scenario {
	case "complete", "panic":
		writePTY(t, master, "\r", " ", "\x1b[D", "\x1b[B", "\r")
	case "ctrl-c":
		writePTY(t, master, "\r", " ", "\x1b[D", "\x03", "y")
	case "resize":
		if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
			t.Fatal(err)
		}
		waitForPTYOutput(t, capture, `Create Profile "pty"`)
		writePTY(t, master, "\x03")
	}

	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatalf("PTY helper failed: %v", err)
		}
	case <-time.After(8 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("PTY helper timed out")
	}
	after, err := readTerminalAttributes(int(master.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-outputDone:
	case <-time.After(2 * time.Second):
		t.Fatal("PTY output reader did not finish")
	}
	return capture.String(), before, after
}

type ptyCapture struct {
	mutex  sync.Mutex
	output strings.Builder
}

func (capture *ptyCapture) Write(contents []byte) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	_, _ = capture.output.Write(contents)
}

func (capture *ptyCapture) String() string {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return capture.output.String()
}

func waitForPTYOutput(t *testing.T, capture *ptyCapture, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(capture.String(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PTY output did not contain %q: %q", marker, capture.String())
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

func TestProfileBuilderPTYHelper(t *testing.T) {
	scenario := os.Getenv(ptyHelperEnvironment)
	if scenario == "" {
		t.Skip("PTY subprocess helper")
	}
	binding, registry := newBuilderFixture(t)
	draft := registry.NewDraft()
	catalog := []skills.SkillBundle{{
		Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
		DisplayName: "review", BundlePath: "/global/review",
	}}
	model := newLoadedSkillsModel(t, "pty", draft, registry, binding, catalog).WithSaver(func(_ context.Context, snapshot category.Draft) (string, error) {
		if scenario == "panic" {
			panic("intentional PTY save panic")
		}
		return "/profiles/pty.json", nil
	})
	ctx := context.Background()
	if scenario == "runtime-error" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()
	}
	outcome, err := Run(ctx, model, os.Stdin, os.Stdout)
	if err != nil {
		if scenario != "panic" && scenario != "runtime-error" {
			t.Fatal(err)
		}
		if scenario == "panic" && !errors.Is(err, tea.ErrProgramPanic) {
			t.Fatalf("panic error = %v", err)
		}
		fmt.Fprintf(os.Stdout, "RUNTIME ERROR: %v\n", err)
		return
	}
	if outcome.Create {
		fmt.Fprintln(os.Stdout, "Created Profile")
		fmt.Fprintln(os.Stdout, "OUTCOME create")
	} else if outcome.Cancelled {
		fmt.Fprintln(os.Stdout, "OUTCOME cancelled")
	}
}

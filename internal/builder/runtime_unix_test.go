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
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

const ptyHelperEnvironment = "ACS_PROFILE_BUILDER_PTY_HELPER"

func TestProfileBuilderPTYRestoresTerminal(t *testing.T) {
	panicMarkers := []string{"RUNTIME ERROR", "program experienced a panic", "Profile transaction unknown"}
	panicAfter := []string{"RUNTIME ERROR"}
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
		{name: "recovered panic", scenario: "panic", want: panicMarkers, after: panicAfter},
		{name: "recovered discovery panic", scenario: "discovery-panic", want: []string{"RUNTIME ERROR", "program experienced a panic"}, after: panicAfter},
		{name: "recovered loaded panic", scenario: "loaded-panic", want: []string{"RUNTIME ERROR", "program experienced a panic"}, after: panicAfter},
		{name: "recovered editor panic", scenario: "editor-panic", want: []string{"RUNTIME ERROR", "program experienced a panic"}, after: panicAfter},
		{name: "recovered preview panic", scenario: "prepare-panic", want: []string{"RUNTIME ERROR", "program experienced a panic"}, after: panicAfter},
		{name: "recovered view panic", scenario: "view-panic", want: []string{"RUNTIME ERROR", "program experienced a panic"}, after: panicAfter},
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
			if strings.Contains(test.scenario, "panic") && (strings.Contains(output, "intentional PTY save panic") || strings.Contains(output, "private callback detail") || strings.Contains(output, "Caught panic:")) {
				t.Fatal("callback panic escaped to Bubble Tea or exposed its private payload")
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
	case "discovery-panic", "loaded-panic", "view-panic":
		writePTY(t, master, "\r")
	case "editor-panic":
		writePTY(t, master, "\r", " ")
	case "prepare-panic":
		writePTY(t, master, "\x1b[B", "\r")
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
			t.Fatalf("PTY helper failed: %v\n%q", err, capture.String())
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

func readTerminalAttributes(fileDescriptor int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fileDescriptor, terminalAttributesRequest)
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
	switch scenario {
	case "discovery-panic":
		model.editors[0].loadState = unloaded
		model.editors[0].registration.discover = func(context.Context) (any, error) { panic("private callback detail") }
	case "loaded-panic":
		model.editors[0].loadState = unloaded
		model.editors[0].registration.loaded = func(Editor, any) (Editor, error) { panic("private callback detail") }
	case "editor-panic":
		model.editors[0].editor = panickingEditor{Editor: model.editors[0].editor, update: true}
	case "prepare-panic":
		model.mutation = &MutationOptions{Label: "Create", Prepare: func(category.Draft) (PreparedMutation, error) { panic("private callback detail") }}
	case "view-panic":
		model.editors[0].editor = panickingEditor{Editor: model.editors[0].editor}
	}
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
		if !strings.Contains(scenario, "panic") && scenario != "runtime-error" {
			t.Fatal(err)
		}
		if strings.Contains(scenario, "panic") && (!errors.Is(err, tea.ErrProgramPanic) || outcome.Create || outcome.Cancelled) {
			t.Fatalf("panic error = %v", err)
		}
		if scenario == "panic" {
			var transaction *profilerepo.OutcomeError
			if outcome.Create || outcome.Cancelled || !errors.As(err, &transaction) || transaction.Outcome.State != profilerepo.Unknown || !transaction.Outcome.RecoveryRequired {
				t.Fatalf("panic lost its unknown/recovery-required outcome: %v", err)
			}
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

func TestRuntimeReportsViewPanicDuringCancellation(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	model := newLoadedSkillsModel(t, "panic", registry.NewDraft(), registry, binding, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, master) }()
	ready := make(chan struct{})
	model.screen = categoryScreen
	model.editors[0].editor = cancellationViewEditor{Editor: model.editors[0].editor, ctx: ctx, ready: ready, once: &sync.Once{}}
	finished := make(chan error, 1)
	go func() {
		outcome, err := Run(ctx, model, terminal, terminal)
		if outcome.Create || outcome.Cancelled {
			err = errors.New("render panic returned success or ordinary cancellation")
		}
		finished <- err
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("initial view did not render")
	}
	// The cancellation watcher requests Quit. Rendering again during shutdown
	// must still report a panic even if the watcher has already stopped.
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, tea.ErrProgramPanic) {
			t.Fatalf("shutdown redraw lost its panic: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("view panic did not finish orderly shutdown")
	}
}

type cancellationViewEditor struct {
	Editor
	ctx   context.Context
	ready chan struct{}
	once  *sync.Once
}

func (editor cancellationViewEditor) View() tea.View {
	if editor.ctx.Err() != nil {
		panic("private callback detail")
	}
	editor.once.Do(func() { close(editor.ready) })
	return editor.Editor.View()
}

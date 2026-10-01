//go:build darwin

package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const (
	seatbeltTerminalProbeInput  = "acs-test-owned-terminal-input"
	seatbeltTerminalProbeOutput = "acs-test-owned-terminal-output"
	seatbeltTerminalProbeOK     = "terminal-isolation-ok"
)

// Every terminal used here is allocated by the test. In particular, the denial
// probes never enumerate or attempt to open a developer's real terminal.
func TestSeatbeltNativeRestrictsTerminalAccessToInheritedPTYs(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, mode := range []string{"stdin", "stdout", "stderr", "distinct-stdio", "headless"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSeatbeltTerminalNativeFixture(t)
			request := fixture.request
			_, neighbor := seatbeltTerminalNativePair(t)
			link := filepath.Join(request.workspace, "unrelated-terminal")
			if err := os.Symlink(neighbor.Name(), link); err != nil {
				t.Fatal(fixture.diagnostic(err))
			}
			// Permission failures must come from containment, not an unavailable
			// terminal or a broken symlink. Retain both endpoints throughout.
			seatbeltTerminalNativeOpenControls(t, fixture, neighbor.Name(), link)
			var output bytes.Buffer
			request.terminal = Terminal{Output: &output, ErrorOutput: &output}
			result := filepath.Join(request.sessionDirectory, "terminal-result")
			request.arguments = []string{
				"-test.run=^TestSeatbeltTerminalNativeHelper$", "--", "isolated",
				result, neighbor.Name(), link,
			}
			var masters []*os.File
			for _, stream := range []string{"stdin", "stdout", "stderr"} {
				if mode != stream && mode != "distinct-stdio" {
					continue
				}
				master, terminal := seatbeltTerminalNativePair(t)
				if err := seatbeltTerminalNativeRaw(terminal); err != nil {
					t.Fatal(err)
				}
				if err := seatbeltTerminalNativeWrite(master, seatbeltTerminalProbeInput); err != nil {
					t.Fatal(err)
				}
				masters = append(masters, master)
				request.arguments = append(request.arguments, terminal.Name())
				switch stream {
				case "stdin":
					request.terminal.Input = terminal
				case "stdout":
					request.terminal.Output = terminal
				case "stderr":
					request.terminal.ErrorOutput = terminal
				}
			}
			fixture.settled = false
			settled, err := seatbeltTerminalNativeRun(request)
			fixture.settled = settled
			if err != nil {
				t.Fatalf("terminal isolation failed: %s; result=%q; output=%q", fixture.diagnostic(err), fixture.diagnostic(string(readSeatbeltPTYFile(result))), fixture.diagnostic(output.String()))
			}
			if got := string(readSeatbeltPTYFile(result)); got != seatbeltTerminalProbeOK {
				t.Fatalf("terminal result = %q, want %q; output=%q", fixture.diagnostic(got), seatbeltTerminalProbeOK, fixture.diagnostic(output.String()))
			}
			for _, master := range masters {
				if err := seatbeltTerminalNativeRead(master, seatbeltTerminalProbeOutput); err != nil {
					t.Fatal(err)
				}
			}
			seatbeltTerminalNativeOpenControls(t, fixture, neighbor.Name(), link)
		})
	}
}

// The outer harness establishes a disposable controlling terminal, then
// redirects all three target streams. /dev/tty must still refer to that
// controlling terminal. Do not read from it: redirected stdin deliberately
// retains the existing backend's foreground-process-group behavior.
func TestSeatbeltNativeRetainsControllingTTYWithRedirectedStdio(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	fixture := newSeatbeltTerminalNativeFixture(t)
	request := fixture.request
	root := fixture.root
	master, terminal := seatbeltTerminalNativePair(t)
	if err := seatbeltTerminalNativeRaw(terminal); err != nil {
		t.Fatal(err)
	}
	// Drain while the session leader is alive. Darwin can wait for unread
	// controlling-terminal output during exit, so Wait-before-read deadlocks
	// even when the output is smaller than the PTY buffer and SIGKILL is sent.
	output := &seatbeltBoundedCapture{limit: 4096}
	drainCancel := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() { drainDone <- seatbeltTerminalNativeDrain(master, output, drainCancel) }()
	drainStopped := false
	stopDrain := func() {
		if drainStopped {
			return
		}
		drainStopped = true
		close(drainCancel)
		select {
		case err := <-drainDone:
			if err != nil {
				t.Errorf("controlling-terminal output drain: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("controlling-terminal output drain did not honor cancellation")
		}
	}
	defer stopDrain()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSeatbeltTerminalNativeHelper$", "--", "controlling-harness", root)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	command.WaitDelay = time.Second
	result := filepath.Join(request.sessionDirectory, "terminal-result")
	fixture.settled = false
	if err := command.Start(); err != nil {
		fixture.settled = true // No harness or contained target started.
		t.Fatalf("start controlling-terminal harness: %s", fixture.diagnostic(err))
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var waitErr error
	waitSettled := true
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		_ = command.Process.Kill()
		select {
		case waitErr = <-waitDone:
		case <-time.After(5 * time.Second):
			waitSettled = false
		}
		waitErr = errors.Join(waitErr, ctx.Err())
	}
	stopDrain()
	// This receipt is outside the sandbox-writable Session and can only be
	// published by the trusted harness after authenticated backend cleanup.
	fixture.settled = waitSettled && string(readSeatbeltPTYFile(filepath.Join(root, "harness-cleanup-proven"))) == seatbeltTerminalProbeOK
	if waitErr != nil || !fixture.settled {
		t.Fatalf("redirected controlling terminal failed: %s; cleanup=%v; stage=%q; result=%q; output=%q", fixture.diagnostic(waitErr), fixture.settled, readSeatbeltPTYFile(filepath.Join(root, "harness-stage")), fixture.diagnostic(string(readSeatbeltPTYFile(result))), fixture.diagnostic(output.String()))
	}
	if got := string(readSeatbeltPTYFile(result)); got != seatbeltTerminalProbeOK {
		t.Fatalf("redirected terminal result = %q, want %q", fixture.diagnostic(got), seatbeltTerminalProbeOK)
	}
	if output.Exceeded() || output.String() != seatbeltTerminalProbeOutput {
		t.Fatalf("controlling-terminal write = %q, exceeded=%v; want %q", fixture.diagnostic(output.String()), output.Exceeded(), seatbeltTerminalProbeOutput)
	}
}

func seatbeltTerminalNativeDrain(master *os.File, output *seatbeltBoundedCapture, cancel <-chan struct{}) error {
	descriptor := int(master.Fd())
	if err := unix.SetNonblock(descriptor, true); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	for {
		select {
		case <-cancel:
			return nil
		default:
		}
		count, err := unix.Read(descriptor, buffer)
		if count > 0 {
			_, _ = output.Write(buffer[:count])
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) {
			select {
			case <-cancel:
				return nil
			case <-time.After(time.Millisecond):
				continue
			}
		}
		// A controlling-terminal revoke can report EIO at PTY EOF. The outer
		// test still requires the entire exact payload and authenticated cleanup.
		if errors.Is(err, syscall.EIO) || count == 0 && err == nil {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func TestSeatbeltTerminalNativeDrainCancelsWithOpenSlave(t *testing.T) {
	master, terminal := seatbeltTerminalNativePair(t)
	output := &seatbeltBoundedCapture{limit: 4096}
	cancel := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- seatbeltTerminalNativeDrain(master, output, cancel) }()
	defer func() {
		close(cancel)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("drain disposable PTY: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("drain failed to stop while slave remained open")
		}
	}()
	if err := seatbeltTerminalNativeWrite(terminal, seatbeltTerminalProbeOutput); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for output.String() != seatbeltTerminalProbeOutput {
		if output.Exceeded() || time.Now().After(deadline) {
			t.Fatalf("active drain output = %q, want %q", output.String(), seatbeltTerminalProbeOutput)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSeatbeltTerminalNativeHelper(t *testing.T) {
	var arguments []string
	for index, argument := range os.Args {
		if argument == "--" {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) == 0 {
		return
	}
	var err error
	var result string
	switch arguments[0] {
	case "isolated":
		if len(arguments) < 4 {
			os.Exit(125)
		}
		result = arguments[1]
		err = seatbeltTerminalNativeIsolated(arguments[2], arguments[3], arguments[4:])
	case "created":
		if len(arguments) != 3 {
			os.Exit(125)
		}
		err = seatbeltTerminalNativeCreated(arguments[1], arguments[2])
	case "controlling-harness":
		if len(arguments) != 2 {
			os.Exit(125)
		}
		_ = os.WriteFile(filepath.Join(arguments[1], "harness-stage"), []byte("preparing"), 0o600)
		var request validatedProcessRequest
		request, err = seatbeltNativePTYRequest(arguments[1])
		if err == nil {
			result = filepath.Join(request.sessionDirectory, "terminal-result")
			request.arguments = []string{"-test.run=^TestSeatbeltTerminalNativeHelper$", "--", "controlling", result}
			var output bytes.Buffer
			request.terminal = Terminal{Input: strings.NewReader(""), Output: &output, ErrorOutput: &output}
			var settled bool
			_ = os.WriteFile(filepath.Join(arguments[1], "harness-stage"), []byte("running"), 0o600)
			settled, err = seatbeltTerminalNativeRun(request)
			stage := "cleanup-unproven"
			if settled {
				stage = "cleanup-proven"
			}
			_ = os.WriteFile(filepath.Join(arguments[1], "harness-stage"), []byte(stage), 0o600)
			if settled {
				err = errors.Join(err, os.WriteFile(filepath.Join(arguments[1], "harness-cleanup-proven"), []byte(seatbeltTerminalProbeOK), 0o600))
			}
			if err != nil {
				err = fmt.Errorf("redirected target: %w; output=%q", err, output.String())
			}
		}
	case "controlling":
		if len(arguments) != 2 {
			os.Exit(125)
		}
		result = arguments[1]
		err = seatbeltTerminalNativeControlling()
	default:
		os.Exit(125)
	}
	message := seatbeltTerminalProbeOK
	if err != nil {
		message = err.Error()
	}
	if result != "" {
		if writeErr := os.WriteFile(result, []byte(message), 0o600); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Avoid the testing package's PASS output on terminals under byte-for-byte
	// I/O observation, including in the nested dynamically allocating child.
	os.Exit(0)
}

func seatbeltTerminalNativeIsolated(neighbor, link string, attached []string) error {
	for _, path := range []string{neighbor, link} {
		if err := seatbeltTerminalNativeDenied(path); err != nil {
			return err
		}
	}
	for _, path := range attached {
		terminal, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("reopen attached PTY: %w", err)
		}
		err = seatbeltTerminalNativeIOCTL(terminal)
		if err == nil {
			err = seatbeltTerminalNativeRead(terminal, seatbeltTerminalProbeInput)
		}
		if err == nil {
			err = seatbeltTerminalNativeWrite(terminal, seatbeltTerminalProbeOutput)
		}
		_ = terminal.Close()
		if err != nil {
			return fmt.Errorf("attached PTY: %w", err)
		}
	}
	// Allocate after containment and after an exec boundary; no attached path
	// grant can name this PTY. The extension must authorize this child only.
	command := exec.Command(os.Args[0], "-test.run=^TestSeatbeltTerminalNativeHelper$", "--", "created", neighbor, link)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("descendant-created PTY: %w; output=%q", err, output)
	}
	// Creating a PTY must not turn its extension into access to another PTY.
	for _, path := range []string{neighbor, link} {
		if err := seatbeltTerminalNativeDenied(path); err != nil {
			return err
		}
	}
	return nil
}

func seatbeltTerminalNativeCreated(neighbor, link string) error {
	master, terminal, err := pty.Open()
	if err != nil {
		return fmt.Errorf("pty.Open: %w", err)
	}
	defer master.Close()
	defer terminal.Close()
	// Check from the process that acquired the extension, while its own PTY is
	// still open. An overly broad extension grant must not admit the neighbor.
	for _, path := range []string{neighbor, link} {
		if err := seatbeltTerminalNativeDenied(path); err != nil {
			return err
		}
	}
	if err := seatbeltTerminalNativeIOCTL(terminal); err != nil {
		return err
	}
	// Reopen by name as well as using the descriptor returned by pty.Open.
	reopened, err := os.OpenFile(terminal.Name(), os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("reopen created PTY: %w", err)
	}
	defer reopened.Close()
	if err := seatbeltTerminalNativeWrite(master, seatbeltTerminalProbeInput); err != nil {
		return err
	}
	if err := seatbeltTerminalNativeRead(reopened, seatbeltTerminalProbeInput); err != nil {
		return err
	}
	if err := seatbeltTerminalNativeWrite(reopened, seatbeltTerminalProbeOutput); err != nil {
		return err
	}
	return seatbeltTerminalNativeRead(master, seatbeltTerminalProbeOutput)
}

func seatbeltTerminalNativeControlling() error {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open controlling alias: %w", err)
	}
	defer terminal.Close()
	if _, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TIOCGETA); err != nil {
		return fmt.Errorf("controlling alias termios ioctl: %w", err)
	}
	if _, err := pty.GetsizeFull(terminal); err != nil {
		return fmt.Errorf("controlling alias window-size ioctl: %w", err)
	}
	return seatbeltTerminalNativeWrite(terminal, seatbeltTerminalProbeOutput)
}

func seatbeltTerminalNativeDenied(path string) error {
	for _, access := range []int{os.O_RDONLY, os.O_WRONLY, os.O_RDWR} {
		file, err := os.OpenFile(path, access|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = file.Close()
			return fmt.Errorf("unrelated PTY open unexpectedly allowed (access=%d, path=%q)", access, path)
		}
		if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
			return fmt.Errorf("unrelated PTY failed without a permission denial (access=%d): %w", access, err)
		}
	}
	return nil
}

func seatbeltTerminalNativePair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = terminal.Close() })
	return master, terminal
}

func seatbeltTerminalNativeOpenControls(t *testing.T, fixture *seatbeltTerminalNativeFixture, paths ...string) {
	t.Helper()
	for _, path := range paths {
		for _, access := range []int{os.O_RDONLY, os.O_WRONLY, os.O_RDWR} {
			file, err := os.OpenFile(path, access|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatalf("unsandboxed disposable PTY control (access=%d): %s", access, fixture.diagnostic(err))
			}
			_ = file.Close()
		}
	}
}

type seatbeltTerminalNativeFixture struct {
	request validatedProcessRequest
	root    string
	settled bool
}

func newSeatbeltTerminalNativeFixture(t *testing.T) *seatbeltTerminalNativeFixture {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "acs-seatbelt-terminal-")
	if err != nil {
		t.Fatal("create disposable terminal fixture")
	}
	request, err := seatbeltNativePTYRequest(root)
	if err != nil {
		_ = os.RemoveAll(root)
		t.Fatal("prepare disposable terminal fixture")
	}
	fixture := &seatbeltTerminalNativeFixture{request: request, root: root, settled: true}
	t.Cleanup(func() {
		if fixture.settled {
			_ = os.RemoveAll(root)
		} else {
			t.Log("retaining terminal fixture because contained cleanup is unproven")
		}
	})
	return fixture
}

func (fixture *seatbeltTerminalNativeFixture) diagnostic(value any) string {
	return strings.ReplaceAll(fmt.Sprint(value), fixture.root, "<fixture>")
}

// Return settlement separately from the target's exit status: even a failed
// target can be safely removed after proof, while an unproven fixture must stay.
func seatbeltTerminalNativeRun(request validatedProcessRequest) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(ctx, request)
	if err != nil {
		return true, err // The contained target was never started.
	}
	startErr := process.Start()
	var waitErr error
	waitSettled := true
	if startErr == nil {
		waitDone := make(chan error, 1)
		go func() { waitDone <- process.Wait() }()
		select {
		case waitErr = <-waitDone:
		case <-ctx.Done():
			_ = process.Signal(syscall.SIGKILL)
			select {
			case waitErr = <-waitDone:
			case <-time.After(5 * time.Second):
				waitSettled = false
			}
			waitErr = errors.Join(waitErr, ctx.Err())
		}
	} else {
		// Start already owns reaping any partially started supervisor. A second
		// Wait would race its reaper; cancellation and CleanupDone decide safety.
		cancel()
	}
	cleanup, ok := process.(ProcessCleanup)
	if !ok || cleanup.CleanupDone() == nil {
		return false, errors.Join(startErr, waitErr, errors.New("terminal probe has no authenticated cleanup notification"))
	}
	select {
	case <-cleanup.CleanupDone():
		seatbelt, ok := process.(*seatbeltProcess)
		if !ok {
			return waitSettled, errors.Join(startErr, waitErr, errors.New("terminal probe did not use the native Seatbelt process"))
		}
		for index, pin := range seatbelt.terminalPins {
			if _, err := pin.Stat(); !errors.Is(err, os.ErrClosed) {
				return waitSettled, errors.Join(startErr, waitErr, fmt.Errorf("terminal pin %d was not closed after authenticated cleanup", index))
			}
		}
		return waitSettled, errors.Join(startErr, waitErr)
	case <-time.After(5 * time.Second):
		return false, errors.Join(startErr, waitErr, errors.New("terminal probe cleanup did not finish; fixture retained"))
	}
}

func seatbeltTerminalNativeRaw(file *os.File) error {
	settings, err := unix.IoctlGetTermios(int(file.Fd()), unix.TIOCGETA)
	if err != nil {
		return err
	}
	settings.Lflag &^= unix.ICANON | unix.ECHO | unix.TOSTOP
	settings.Oflag &^= unix.OPOST
	settings.Cc[unix.VMIN] = 1
	settings.Cc[unix.VTIME] = 0
	return unix.IoctlSetTermios(int(file.Fd()), unix.TIOCSETA, settings)
}

func seatbeltTerminalNativeIOCTL(file *os.File) error {
	if err := seatbeltTerminalNativeRaw(file); err != nil {
		return fmt.Errorf("termios get/set ioctl: %w", err)
	}
	want := &pty.Winsize{Rows: 37, Cols: 109}
	if err := pty.Setsize(file, want); err != nil {
		return fmt.Errorf("window-size set ioctl: %w", err)
	}
	got, err := pty.GetsizeFull(file)
	if err != nil || *got != *want {
		return fmt.Errorf("window-size get ioctl = %v, %v; want %v", got, err, want)
	}
	return nil
}

func seatbeltTerminalNativeWrite(file *os.File, want string) error {
	descriptor := int(file.Fd())
	if err := unix.SetNonblock(descriptor, true); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for remaining := []byte(want); len(remaining) > 0; {
		count, err := unix.Write(descriptor, remaining)
		if count > 0 {
			remaining = remaining[count:]
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("timed out writing disposable PTY")
		}
		if len(remaining) > 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return nil
}

func seatbeltTerminalNativeRead(file *os.File, want string) error {
	descriptor := int(file.Fd())
	if err := unix.SetNonblock(descriptor, true); err != nil {
		return err
	}
	contents := make([]byte, len(want))
	deadline := time.Now().Add(2 * time.Second)
	for offset := 0; offset < len(contents); {
		count, err := unix.Read(descriptor, contents[offset:])
		if count > 0 {
			offset += count
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if count == 0 && err == nil {
			return io.ErrUnexpectedEOF
		}
		if time.Now().After(deadline) {
			return errors.New("timed out reading disposable PTY")
		}
		if offset < len(contents) {
			time.Sleep(time.Millisecond)
		}
	}
	if string(contents) != want {
		return fmt.Errorf("disposable PTY read = %q, want %q", contents, want)
	}
	return nil
}

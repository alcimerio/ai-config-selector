//go:build darwin

package launch

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/creack/pty"
)

func TestSeatbeltPolicyLimitsInheritedTerminalToExactDevice(t *testing.T) {
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	request := validatedProcessRequest{workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/bin/zsh", terminal: Terminal{Input: terminal, Output: terminal, ErrorOutput: terminal}}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	var terminalDefinitions []string
	for _, definition := range definitions {
		if strings.HasPrefix(definition, "-DTERMINAL_") {
			terminalDefinitions = append(terminalDefinitions, definition)
		}
	}
	if len(terminalDefinitions) != 1 || terminalDefinitions[0] != "-DTERMINAL_0="+terminal.Name() {
		t.Fatalf("expected exactly the attached PTY definition, got %d", len(terminalDefinitions))
	}
	if !strings.Contains(policy, `(literal (param "TERMINAL_0"))`) {
		t.Fatal("attached terminal literal missing")
	}
	for _, line := range strings.Split(policy, "\n") {
		if strings.Contains(line, `regex #"^/dev/ttys`) && !strings.Contains(line, `(require-all (regex #"^/dev/ttys[0-9]+$") (extension "com.apple.sandbox.pty"))`) {
			t.Fatal("terminal pattern lacks the exact ownership-extension conjunction")
		}
	}
	if !strings.Contains(policy, `(extension "com.apple.sandbox.pty")`) {
		t.Fatal("owned child PTY extension missing")
	}
}

func TestSeatbeltPolicyHeadlessDoesNotGrantNamedTerminals(t *testing.T) {
	request := validatedProcessRequest{workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/bin/zsh", terminal: Terminal{Input: strings.NewReader(""), Output: &strings.Builder{}, ErrorOutput: &strings.Builder{}}}
	_, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range definitions {
		if strings.HasPrefix(definition, "-DTERMINAL_") {
			t.Fatal("headless launch grants a named terminal")
		}
	}
}

func TestSeatbeltTerminalDiscoveryIgnoresNonTerminalFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "redirected-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	request := validatedProcessRequest{workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/bin/zsh", terminal: Terminal{Input: file, Output: file, ErrorOutput: file}}
	_, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range definitions {
		if strings.Contains(definition, file.Name()) {
			t.Fatal("redirected file received a path grant")
		}
	}
}

func TestSeatbeltTerminalPathValidationIsExact(t *testing.T) {
	for _, path := range []string{"/dev/tty", "/dev/ttys000", "/dev/ttys12"} {
		if !validSeatbeltTerminalPath(path) {
			t.Errorf("valid terminal spelling rejected")
		}
	}
	for _, path := range []string{"", "/dev/ttys", "/dev/ttys1x", "/dev/ttys1/child", "/dev/ttys1\n", "/dev/../dev/ttys1", "/dev/ptmx", "/tmp/ttys1"} {
		if validSeatbeltTerminalPath(path) {
			t.Errorf("invalid terminal spelling accepted")
		}
	}
}

func TestSeatbeltTerminalDiscoveryUsesDescriptorNotFileName(t *testing.T) {
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	fd, err := unix.FcntlInt(terminal.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	misleading := os.NewFile(uintptr(fd), "/dev/ttys999999")
	defer misleading.Close()
	paths, err := seatbeltTerminalPaths(Terminal{Input: misleading, Output: terminal})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != terminal.Name() {
		t.Fatal("terminal authority did not follow the opened descriptor")
	}
}

func TestSeatbeltTerminalDiscoveryRejectsClosedDescriptor(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := seatbeltTerminalPaths(Terminal{Input: file}); err == nil {
		t.Fatal("closed descriptor accepted")
	}
	if _, _, err := pinSeatbeltTerminal(Terminal{Input: file}); err == nil {
		t.Fatal("closed descriptor pinned")
	}
}

func TestSeatbeltTerminalPinsRetainDeviceUntilCleanupProof(t *testing.T) {
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	pinned, pins, err := pinSeatbeltTerminal(Terminal{Input: terminal, Output: terminal, ErrorOutput: terminal})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSeatbeltTerminalPins(pins)
	if len(pins) != 1 || pinned.Input != pins[0] || pinned.Output != pins[0] || pinned.ErrorOutput != pins[0] {
		t.Fatal("stdio was not mapped to one owned terminal pin")
	}
	flags, err := unix.FcntlInt(pins[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("terminal pin is not close-on-exec")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := seatbeltTerminalPaths(pinned); err != nil {
		t.Fatal("caller close invalidated pinned terminal")
	}
	process := &seatbeltProcess{terminalPins: pins, cleanupDone: make(chan struct{}), cleanupQuarantine: func(*seatbeltProcess) {}}
	process.quarantineCleanup()
	if _, err := pins[0].Stat(); err != nil {
		t.Fatal("unproven cleanup released terminal pin")
	}
	process.markCleanupDone()
	<-process.CleanupDone()
	if _, err := pins[0].Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("proven cleanup retained terminal pin")
	}
	process.markCleanupDone()
}

func TestSeatbeltTerminalPinsCloseOnPreparationFailure(t *testing.T) {
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	var pin *os.File
	backend := newSeatbeltBackend(seatbeltExecutable)
	backend.policy = func(request validatedProcessRequest) (string, []string, error) {
		pin = request.terminal.Input.(*os.File)
		return "", nil, errors.New("synthetic policy failure")
	}
	if _, err := backend.prepare(context.Background(), validatedProcessRequest{terminal: Terminal{Input: terminal}}); err == nil {
		t.Fatal("expected policy failure")
	}
	if pin == nil || pin == terminal {
		t.Fatal("prepare did not own its terminal descriptor")
	}
	if _, err := pin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("failed prepare retained terminal pin")
	}
	if _, err := terminal.Stat(); err != nil {
		t.Fatal("failed prepare closed caller's terminal")
	}
}

func TestSeatbeltTerminalPinsCloseOnAbortAndStartFailure(t *testing.T) {
	for _, action := range []string{"abort", "start"} {
		t.Run(action, func(t *testing.T) {
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			_, pins, err := pinSeatbeltTerminal(Terminal{Input: terminal})
			if err != nil {
				t.Fatal(err)
			}
			defer closeSeatbeltTerminalPins(pins)
			process := &seatbeltProcess{terminalPins: pins, cleanupDone: make(chan struct{}), command: exec.Command("/acs-nonexistent-terminal-test")}
			restored := false
			if action == "start" {
				process.terminal = pins[0]
				process.setForegroundProcessGroup = func(file *os.File, _ int) error {
					restored = true
					if _, err := file.Stat(); err != nil {
						t.Error("foreground restoration used a closed terminal pin")
					}
					return nil
				}
			}
			if action == "abort" {
				if err := process.AbortPrepared(); err != nil {
					t.Fatal(err)
				}
			} else if err := process.Start(); err == nil {
				t.Fatal("expected start failure")
			}
			<-process.CleanupDone()
			if action == "start" && !restored {
				t.Fatal("start failure did not restore the terminal")
			}
			if _, err := pins[0].Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("unused terminal pin retained")
			}
		})
	}
}

func TestSeatbeltTerminalDiscoveryPreservesRedirectedDescriptors(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(sockets[0]), "redirected-socket")
	peer := os.NewFile(uintptr(sockets[1]), "redirected-peer")
	defer socket.Close()
	defer peer.Close()
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for _, file := range []*os.File{reader, writer, socket, null} {
		original := Terminal{Input: file, Output: file, ErrorOutput: file}
		paths, err := seatbeltTerminalPaths(original)
		if err != nil || len(paths) != 0 {
			t.Fatalf("redirected descriptor discovery: paths=%d error=%v", len(paths), err)
		}
		got, pins, err := pinSeatbeltTerminal(original)
		defer closeSeatbeltTerminalPins(pins)
		if err != nil || len(pins) != 0 || got != original {
			t.Fatalf("redirected descriptor was not preserved: pins=%d error=%v", len(pins), err)
		}
	}
}

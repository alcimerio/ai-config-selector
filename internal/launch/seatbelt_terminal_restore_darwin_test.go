//go:build darwin

package launch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const seatbeltTerminalRestoreRun = "-test.run=^TestSeatbeltTerminalRestoreHelper$"

// seatbeltTerminalRestoreFIONREAD is FIONREAD from <sys/filio.h>.
const seatbeltTerminalRestoreFIONREAD = 0x4004667f

// The target leaves bytes in its controlling terminal's input queue. After
// the backend returns the terminal, nothing written by the target may remain
// pending for the caller.
func TestSeatbeltTerminalRestoreDiscardsPendingInput(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	fixture := newSeatbeltTerminalNativeFixture(t)
	root := fixture.root
	master, terminal := seatbeltTerminalNativePair(t)
	if err := seatbeltTerminalNativeRaw(terminal); err != nil {
		t.Fatal(err)
	}
	output := &seatbeltBoundedCapture{limit: 4096}
	drainCancel := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() { drainDone <- seatbeltTerminalNativeDrain(master, output, drainCancel) }()
	defer func() {
		close(drainCancel)
		<-drainDone
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], seatbeltTerminalRestoreRun, "--", "harness", root)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	command.WaitDelay = time.Second
	fixture.settled = false
	runErr := command.Run()
	fixture.settled = string(readSeatbeltPTYFile(filepath.Join(root, "harness-cleanup-proven"))) == seatbeltTerminalProbeOK
	target := string(readSeatbeltPTYFile(filepath.Join(root, "target-result")))
	pending := string(readSeatbeltPTYFile(filepath.Join(root, "pending-input")))
	t.Logf("target=%q pending_after_restore=%q", fixture.diagnostic(target), pending)
	if runErr != nil || !fixture.settled {
		t.Fatalf("terminal restore harness failed: %s; cleanup=%v", fixture.diagnostic(runErr), fixture.settled)
	}
	if pending != "0" {
		t.Fatalf("terminal input pending after restore = %q, want 0", pending)
	}
}

func TestSeatbeltTerminalRestoreHelper(t *testing.T) {
	var arguments []string
	for index, argument := range os.Args {
		if argument == "--" {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) != 2 {
		return
	}
	switch arguments[0] {
	case "harness":
		os.Exit(seatbeltTerminalRestoreHarness(arguments[1]))
	case "queue":
		_ = os.WriteFile(arguments[1], []byte(seatbeltTerminalRestoreQueueInput()), 0o600)
		os.Exit(0)
	}
	os.Exit(125)
}

func seatbeltTerminalRestoreHarness(root string) int {
	request, err := seatbeltNativePTYRequest(root)
	if err != nil {
		return 93
	}
	result := filepath.Join(request.sessionDirectory, "queue-result")
	request.arguments = []string{seatbeltTerminalRestoreRun, "--", "queue", result}
	request.terminal = Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}
	settled, runErr := seatbeltTerminalNativeRun(request)
	pending, pendingErr := unix.IoctlGetInt(int(os.Stdin.Fd()), seatbeltTerminalRestoreFIONREAD)
	record := strconv.Itoa(pending)
	if pendingErr != nil {
		record = "error: " + pendingErr.Error()
	}
	_ = os.WriteFile(filepath.Join(root, "pending-input"), []byte(record), 0o600)
	target := string(readSeatbeltPTYFile(result))
	if runErr != nil {
		target += fmt.Sprintf(" run_err=%v", runErr)
	}
	_ = os.WriteFile(filepath.Join(root, "target-result"), []byte(target), 0o600)
	if settled {
		_ = os.WriteFile(filepath.Join(root, "harness-cleanup-proven"), []byte(seatbeltTerminalProbeOK), 0o600)
	}
	if runErr != nil {
		return 1
	}
	return 0
}

// seatbeltTerminalRestoreQueueInput returns "queued", or the first failure.
func seatbeltTerminalRestoreQueueInput() string {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return "open-error: " + err.Error()
	}
	defer terminal.Close()
	for _, value := range []byte("acs-test-input\n") {
		character := value
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, terminal.Fd(), uintptr(unix.TIOCSTI), uintptr(unsafe.Pointer(&character))); errno != 0 {
			return "ioctl-error: " + errno.Error()
		}
	}
	return "queued"
}

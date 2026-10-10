package launch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxDiagnosticProcessHelper(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if mode != "acs-diagnostic-exit" && mode != "acs-diagnostic-signal" {
		return
	}
	// The protocol closes before the final diagnostic is flushed. The parent
	// must wait for the process instead of racing a bytes.Buffer read with Wait.
	_ = os.NewFile(3, "owner").Close()
	time.Sleep(10 * time.Millisecond)
	fmt.Fprintln(os.Stderr, "contained init: test setup step: operation not permitted")
	if mode == "acs-diagnostic-signal" {
		_ = unix.Kill(os.Getpid(), unix.SIGKILL)
	}
	os.Exit(125)
}

func TestLinuxProtocolFailureIncludesSupervisorDiagnostics(t *testing.T) {
	for _, tc := range []struct{ mode, exit string }{
		{"exit", "exit status 125"},
		{"signal", "signal: killed"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			owner, client := linuxTestSocketpair(t)
			cmd := exec.Command("/proc/self/exe", "-test.run=^TestLinuxDiagnosticProcessHelper$", "--", "acs-diagnostic-"+tc.mode)
			cmd.ExtraFiles = []*os.File{client}
			process := linuxNativeStartCommand(t, cmd)
			_ = client.Close()
			err := linuxReadTestByte(owner, 'R', process.diagnostics)
			if err == nil {
				t.Fatal("early exit passed the readiness assertion")
			}
			for _, want := range []string{"EOF", "want 'R'", tc.exit, "contained init: test setup step: operation not permitted"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("missing %q in %s", want, err)
				}
			}
		})
	}
	called := false
	if err := linuxReadTestByte(strings.NewReader("R"), 'R', func() string { called = true; return "" }); err != nil || called {
		t.Fatal("successful protocol read collected failure diagnostics")
	}
}

func TestLinuxSessionClosedDelegationReportsStepAndErrno(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = parent.Close()
	_, err = linuxCreateSessionCgroup(parent)
	if !errors.Is(err, errLinuxContainment) || !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "verify cgroup v2 filesystem") {
		t.Fatalf("lost setup step or syscall error: %v", err)
	}
}

func TestLinuxContainedInitSetupFailureReportsStep(t *testing.T) {
	status, report := linuxTestSocketpair(t)
	control, gate := linuxTestSocketpair(t)
	defer status.Close()
	defer gate.Close()
	err := linuxRunContainedInit(linuxLaunchWire{}, nil, report, control)
	if !errors.Is(err, errLinuxContainment) || !strings.Contains(err.Error(), "contained init: validate transport and control descriptors") {
		t.Fatalf("lost contained-init setup step: %v", err)
	}
}

func TestLinuxRestrictedFailureDiagnostics(t *testing.T) {
	frame := []byte{10, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(frame[1:], uint32(unix.EBADF))
	err := linuxReadRestrictedFailure(strings.NewReader(string(frame)))
	if !errors.Is(err, errLinuxSeal) || !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "landlock_restrict_self") {
		t.Fatalf("lost raw setup stage or errno: %v", err)
	}
	for _, invalid := range []string{"", "\x01", "\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00"} {
		if err := linuxReadRestrictedFailure(strings.NewReader(invalid)); !errors.Is(err, errLinuxSeal) {
			t.Fatalf("invalid diagnostic frame accepted: %q: %v", invalid, err)
		}
	}
}

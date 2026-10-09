package executor

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestDevinSignalSupervisorCleanupModeNoticesThenForcesExit(t *testing.T) {
	canceled := 0
	supervisor := newDevinSignalSupervisor(func() { canceled++ })
	defer supervisor.stop()
	var notice bytes.Buffer
	var forced []os.Signal
	supervisor.setNotice(&notice)
	supervisor.forceExit = func(received os.Signal) { forced = append(forced, received) }

	supervisor.beginCleanup()
	supervisor.handleSignal(syscall.SIGWINCH)
	if notice.Len() != 0 || len(forced) != 0 {
		t.Fatalf("resize during cleanup produced notice %q / forced %v", notice.String(), forced)
	}
	supervisor.handleSignal(os.Interrupt)
	if !strings.Contains(notice.String(), "press Ctrl-C again") || len(forced) != 0 {
		t.Fatalf("first Ctrl-C during cleanup: notice %q, forced %v", notice.String(), forced)
	}
	supervisor.handleSignal(syscall.SIGTERM)
	if len(forced) != 1 || forced[0] != syscall.SIGTERM {
		t.Fatalf("second termination during cleanup forced %v, want [SIGTERM]", forced)
	}
	if canceled != 0 {
		t.Fatalf("cleanup-mode signals called cancelPreflight %d times", canceled)
	}
}

func TestDevinSignalSupervisorDetachEntersCleanupMode(t *testing.T) {
	supervisor := newDevinSignalSupervisor(func() {})
	defer supervisor.stop()
	var notice bytes.Buffer
	supervisor.setNotice(&notice)
	supervisor.forceExit = func(os.Signal) { t.Fatal("first Ctrl-C after target exit forced exit") }
	process := &countingSignalProcess{}
	if err := runDevinAttached(process, supervisor); err != nil {
		t.Fatal(err)
	}
	supervisor.handleSignal(os.Interrupt)
	if process.signals != 0 {
		t.Fatalf("signal forwarded to an exited target %d times", process.signals)
	}
	if !strings.Contains(notice.String(), "finishing Session cleanup") {
		t.Fatalf("Ctrl-C after target exit was swallowed silently: %q", notice.String())
	}
}

func TestDevinSignalSupervisorStopIsIdempotent(t *testing.T) {
	supervisor := newDevinSignalSupervisor(func() {})
	supervisor.stop()
	supervisor.stop()
}

type countingSignalProcess struct{ signals int }

func (*countingSignalProcess) Start() error                   { return nil }
func (*countingSignalProcess) Wait() error                    { return nil }
func (process *countingSignalProcess) Signal(os.Signal) error { process.signals++; return nil }

package launch

import (
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type startupSignalProcess struct {
	want        os.Signal
	received    chan struct{}
	receiveOnce sync.Once
	mutex       sync.Mutex
	signals     []os.Signal
	waited      bool
}

func (process *startupSignalProcess) Start() error {
	return syscall.Kill(os.Getpid(), process.want.(syscall.Signal))
}

func (process *startupSignalProcess) Wait() error {
	select {
	case <-process.received:
	case <-time.After(time.Second):
		return &timeoutError{}
	}
	process.waited = true
	return nil
}

func (process *startupSignalProcess) Signal(signal os.Signal) error {
	process.mutex.Lock()
	process.signals = append(process.signals, signal)
	process.mutex.Unlock()
	process.receiveOnce.Do(func() { close(process.received) })
	return nil
}

type timeoutError struct{}

func (*timeoutError) Error() string { return "timed out" }

func TestRunAttachedForwardsSignalReceivedDuringStartupAndWaits(t *testing.T) {
	process := &startupSignalProcess{want: syscall.SIGWINCH, received: make(chan struct{})}

	if err := RunAttached(process); err != nil {
		t.Fatal(err)
	}
	process.mutex.Lock()
	defer process.mutex.Unlock()
	if len(process.signals) != 1 || process.signals[0] != syscall.SIGWINCH {
		t.Fatalf("forwarded signals = %v, want one SIGWINCH", process.signals)
	}
	if !process.waited {
		t.Fatal("RunAttached returned without waiting for the process")
	}
}

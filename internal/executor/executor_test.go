package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type fakeSandbox struct {
	process  *fakeProcess
	prepared int
	checkErr error
}

func (s *fakeSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (s *fakeSandbox) Check(context.Context, launch.SandboxCheck) error { return s.checkErr }
func (s *fakeSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	s.prepared++
	return s.process, nil
}

type fakeProcess struct {
	starts, waits     int
	startErr, waitErr error
	cleanup           <-chan struct{}
}

func (p *fakeProcess) Start() error                 { p.starts++; return p.startErr }
func (p *fakeProcess) Wait() error                  { p.waits++; return p.waitErr }
func (*fakeProcess) Signal(os.Signal) error         { return nil }
func (p *fakeProcess) CleanupDone() <-chan struct{} { return p.cleanup }

func TestRunProbeFailureBlocksTargetAndReapsOnce(t *testing.T) {
	p := &fakeProcess{waitErr: errors.New("probe failed")}
	s := &fakeSandbox{process: p}
	_, err := New(s).Run(context.Background(), Request{SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: t.TempDir(), Recipe: Recipe{Executable: "/fixed", Probes: [][]string{{"probe"}}, Arguments: []string{"target"}}, Terminal: launch.Terminal{Output: io.Discard, ErrorOutput: io.Discard}})
	if err == nil || s.prepared != 1 || p.starts != 1 || p.waits != 1 {
		t.Fatalf("result=%v prepares=%d starts=%d waits=%d", err, s.prepared, p.starts, p.waits)
	}
}

func TestRunFailedStartDoesNotWaitAndKeepsSessionUntilCleanup(t *testing.T) {
	done := make(chan struct{})
	p := &fakeProcess{startErr: errors.New("start"), cleanup: done}
	s := &fakeSandbox{process: p}
	sessions := filepath.Join(t.TempDir(), "sessions")
	_, err := New(s).Run(context.Background(), Request{SessionsDirectory: sessions, WorkingDirectory: t.TempDir(), Recipe: Recipe{Executable: "/fixed", Arguments: []string{"target"}}})
	if err == nil || p.waits != 0 {
		t.Fatalf("result=%v waits=%d", err, p.waits)
	}
	entries, readErr := os.ReadDir(sessions)
	if readErr != nil || len(entries) == 0 {
		t.Fatalf("Session was not retained: %v %v", entries, readErr)
	}
	close(done)
}
